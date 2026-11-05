//! Consensus transaction handling for Willow SDK

use crate::auth::sign_challenge;
use crate::errors::{Result, SignedSubmission, WillowError};
use crate::nonces::{refusal_outcome, AccountNonceState, NonceOutcome, NonceTracker};
use crate::signed_messages::{self, StoreDataTx};
use crate::types::{DidDocument, RegisterSubgroveRequest, SignatureAlgorithm, StoreDataRequest};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Transaction types for consensus - match the working format exactly
pub type Transaction = serde_json::Value;

/// The chain's transaction enum, as the node decodes it.
type ChainTransaction = willow_types::consensus::transactions::Transaction;

/// Register DID transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDidTx {
    pub did_document: DidDocument,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub nonce: u64,
}

/// Update an existing DID document (rotate keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDidTx {
    pub did_document: DidDocument,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub nonce: u64,
}

pub use willow_types::consensus::indexing_transactions::RetentionWindow;

pub use willow_types::consensus::indexing_transactions::SubgroveMode;
pub use willow_types::consensus::transactions::{
    ClaimSubgroveIndexingTx, DeleteDataTx, DeregisterSubgroveTx, FundSubgroveTx,
    RegisterSubgroveTx, TransferTx,
};

/// JSON shape of the on-chain completeness anchor stored at
/// `/store/events_commitment/{subgrove}/{block}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsCommitmentAnchor {
    pub subgrove_id: String,
    pub block_number: u64,
    /// 64-hex chars = the 32-byte commitment.
    pub events_commitment: String,
}

/// What a block reported about a committed transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutcome {
    pub height: i64,
    /// 0 = executed successfully.
    pub code: u32,
    pub log: String,
}

/// CometBFT RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CometBftResponse {
    pub jsonrpc: String,
    pub id: u32,
    pub result: Option<BroadcastResult>,
    pub error: Option<CometBftError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastResult {
    pub code: u32,
    pub data: String,
    pub log: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CometBftError {
    pub code: i32,
    pub message: String,
    pub data: Option<String>,
}

/// What CometBFT answered a `broadcast_tx_sync`.
enum Submission {
    /// CheckTx accepted it, or the mempool already holds these exact bytes; the hash.
    Accepted(String),
    /// CheckTx refused it.
    Refused { code: u32, log: String },
    /// It may or may not have reached the node.
    Unknown(WillowError),
}

/// Consensus client for submitting transactions.
///
/// Every write it signs takes its nonce from a [`NonceTracker`] (one per client, shared by every
/// clone of the [`crate::WillowClient`] that holds it): the lowest nonce in the node's window
/// that the chain doesn't show used and no write in flight from this client holds.
pub struct ConsensusClient {
    http_client: Client,
    consensus_rpc_url: String,
    api_url: Option<String>,
    nonces: Arc<NonceTracker>,
}

impl ConsensusClient {
    /// Create a new consensus client. Its requests time out after
    /// [`crate::client::DEFAULT_TIMEOUT`]; [`Self::with_http_client`] sets another client.
    pub fn new(consensus_rpc_url: &str) -> Self {
        Self {
            http_client: crate::client::http_client_with_timeout(crate::client::DEFAULT_TIMEOUT),
            consensus_rpc_url: consensus_rpc_url.to_string(),
            api_url: None,
            nonces: Arc::new(NonceTracker::new()),
        }
    }

    /// Create a new consensus client with an API URL, which serves an account's base nonce
    /// when the CometBFT RPC doesn't answer its nonce state.
    pub fn new_with_api(consensus_rpc_url: &str, api_url: &str) -> Self {
        Self {
            api_url: Some(api_url.to_string()),
            ..Self::new(consensus_rpc_url)
        }
    }

    /// Send requests with `http_client` (its timeout, proxy, and TLS settings) instead of the
    /// client's own.
    pub fn with_http_client(mut self, http_client: Client) -> Self {
        self.http_client = http_client;
        self
    }

    /// Hand out nonces from `nonces` instead of this client's own tracker, so clients that sign
    /// for the same identity don't take the same nonce.
    pub fn with_nonce_tracker(mut self, nonces: Arc<NonceTracker>) -> Self {
        self.nonces = nonces;
        self
    }

    /// The CometBFT RPC URL transactions and chain-state queries go to.
    pub fn rpc_url(&self) -> &str {
        &self.consensus_rpc_url
    }

    /// The tracker this client hands out nonces from.
    pub fn nonce_tracker(&self) -> &Arc<NonceTracker> {
        &self.nonces
    }

    /// Hand out the next nonce for a write signed by `did`: the lowest in `base + 1 ..= base +
    /// 24` that the chain doesn't show used ([`Self::account_nonce_state`]) and that no write
    /// from this client has taken within the last 120 s.
    ///
    /// The nonce is held for this caller: a write submitted through this client under it settles
    /// it (a CheckTx refusal that doesn't say the nonce is held, used, or spent gives it back),
    /// and an unused one is free again after 120 s. [`WillowError::NonceWindowFull`] when all 24
    /// are taken.
    pub async fn get_next_nonce(&self, did: &str) -> Result<u64> {
        let state = self.account_nonce_state(did).await?;
        self.nonces.take(did, state)
    }

    /// `did`'s nonce state: the ABCI query `/store/account_nonce_state/{did}` over the CometBFT
    /// RPC, the base and which of the 24 nonces above it are used. When the RPC doesn't answer
    /// it, the base alone: from the API's `/account/{did}/nonce` when an API URL is set, else
    /// from `/store/account_nonce/{did}`.
    pub async fn account_nonce_state(&self, did: &str) -> Result<AccountNonceState> {
        if let Ok(Some(value)) = self
            .abci_query_value(&format!("/store/account_nonce_state/{did}"))
            .await
        {
            if let Ok(state) = AccountNonceState::from_bytes(&value) {
                return Ok(state);
            }
        }
        Ok(AccountNonceState {
            base: self.base_nonce(did).await?,
            used: 0,
        })
    }

    /// The account's base nonce alone.
    async fn base_nonce(&self, did: &str) -> Result<u64> {
        if let Some(api_url) = self.api_url.as_ref() {
            let url = format!("{}/account/{}/nonce", api_url.trim_end_matches('/'), did);
            let resp = self
                .http_client
                .get(&url)
                .send()
                .await
                .map_err(|e| WillowError::Network(format!("Failed to fetch nonce: {}", e)))?;
            let body: serde_json::Value = resp.json().await.map_err(|e| {
                WillowError::Network(format!("Failed to parse nonce response: {}", e))
            })?;
            // Response format: {"success": true, "data": {"did": "...", "nonce": N}}
            return Ok(body
                .get("data")
                .and_then(|d| d.get("nonce"))
                .and_then(|n| n.as_u64())
                .unwrap_or(0));
        }
        let value = self
            .abci_query_value(&format!("/store/account_nonce/{did}"))
            .await?
            .unwrap_or_default();
        Ok(AccountNonceState::from_bytes(&value[..value.len().min(8)])?.base)
    }

    /// An ABCI store query over the CometBFT RPC: the value bytes when the node answers code 0
    /// (empty when it has none), `None` for another code.
    async fn abci_query_value(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "abci_query",
            "params": { "path": path, "data": "", "height": "0", "prove": false }
        });
        let resp: serde_json::Value = self
            .http_client
            .post(&self.consensus_rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| WillowError::Network(format!("abci_query {path}: {e}")))?
            .json()
            .await
            .map_err(|e| WillowError::Network(format!("abci_query {path}: {e}")))?;
        let response = resp
            .get("result")
            .and_then(|r| r.get("response"))
            .ok_or_else(|| WillowError::Network(format!("abci_query {path}: no response")))?;
        if response["code"].as_u64().unwrap_or(0) != 0 {
            return Ok(None);
        }
        let value = response["value"].as_str().unwrap_or("");
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map(Some)
            .map_err(|e| WillowError::Network(format!("abci_query {path}: value: {e}")))
    }

    /// Read a block's on-chain completeness anchor — the 32-byte
    /// `events_commitment` — from chain state via the CometBFT RPC.
    ///
    /// Queries the validator's ABCI store at
    /// `/store/events_commitment/{subgrove_id}/{block_number}`. On a hit
    /// (`response.code == 0`) the value bytes are JSON
    /// `{ "subgrove_id", "block_number", "events_commitment": "<64-hex>" }`;
    /// the 32-byte commitment is the hex-decoded `events_commitment`. An anchor that names another
    /// subgrove or block is refused.
    ///
    /// The node answers this query without a proof, so the commitment is the RPC node's word.
    ///
    /// Returns `Ok(None)` when the chain has no commitment for the block
    /// (a non-zero ABCI code, e.g. "No events commitment for block N", or an
    /// empty value) — the block is not completeness-verifiable.
    pub async fn events_commitment(
        &self,
        subgrove_id: &str,
        block_number: u64,
    ) -> Result<Option<[u8; 32]>> {
        let path = format!("/store/events_commitment/{}/{}", subgrove_id, block_number);
        let bytes = match self.abci_query_value(&path).await {
            Ok(Some(bytes)) if !bytes.is_empty() => bytes,
            Ok(_) => return Ok(None),
            Err(e) => {
                return Err(WillowError::Network(format!(
                    "Failed to fetch events_commitment: {e}"
                )))
            }
        };
        let anchor: EventsCommitmentAnchor = serde_json::from_slice(&bytes)?;
        if anchor.subgrove_id != subgrove_id || anchor.block_number != block_number {
            return Err(WillowError::Validation(format!(
                "the events_commitment anchor answered for {subgrove_id} block {block_number} \
                 names {} block {}",
                anchor.subgrove_id, anchor.block_number
            )));
        }
        let commitment_bytes = hex::decode(&anchor.events_commitment)?;
        if commitment_bytes.len() != 32 {
            return Err(WillowError::Validation(format!(
                "events_commitment is {} bytes, expected 32",
                commitment_bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&commitment_bytes);
        Ok(Some(out))
    }

    /// The chain's form of a transaction built as JSON by [`Self::serialize_tx`].
    fn to_chain_transaction<T: Serialize>(variant_name: &str, tx: &T) -> Result<ChainTransaction> {
        serde_json::from_str(&Self::serialize_tx(variant_name, tx)?)
            .map_err(WillowError::Serialization)
    }

    /// Register a DID through consensus
    pub async fn register_did(
        &self,
        did_document: &DidDocument,
        private_key_hex: &str,
        public_key_id: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<String> {
        let did_doc_json = serde_json::to_string(did_document)?;
        let signature_hex = sign_challenge(&did_doc_json, private_key_hex, algorithm)?;
        let signature_bytes = hex::decode(signature_hex)?;
        self.submit_with_nonce(&did_document.id, |nonce| {
            Self::to_chain_transaction(
                "RegisterDid",
                &RegisterDidTx {
                    did_document: did_document.clone(),
                    signature: signature_bytes,
                    public_key_id: public_key_id.to_string(),
                    nonce,
                },
            )
        })
        .await
    }

    /// Update (rotate) an existing DID document.
    ///
    /// `new_did_document` is the replacement document — its `id` must match
    /// the on-chain DID being updated. `current_private_key_hex` is the
    /// **current** signing key (the one already on chain), and
    /// `current_public_key_id` identifies that current key in the on-chain
    /// document. After this tx commits, only keys in
    /// `new_did_document.authentication` are valid for signing as this DID.
    pub async fn update_did(
        &self,
        new_did_document: &DidDocument,
        current_private_key_hex: &str,
        current_public_key_id: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<String> {
        self.submit_with_nonce(&new_did_document.id, |nonce| {
            Self::update_did_transaction(
                new_did_document,
                current_private_key_hex,
                current_public_key_id,
                algorithm,
                nonce,
            )
        })
        .await
    }

    /// Same as [`ConsensusClient::update_did`] with the nonce supplied instead
    /// of fetched. Lets a caller resolve the nonce, show the operator the exact
    /// message that will be signed, and then submit that same message. The nonce is held for
    /// this write in the client's tracker and settled by its outcome.
    pub async fn update_did_with_nonce(
        &self,
        new_did_document: &DidDocument,
        current_private_key_hex: &str,
        current_public_key_id: &str,
        algorithm: SignatureAlgorithm,
        nonce: u64,
    ) -> Result<String> {
        let tx = Self::update_did_transaction(
            new_did_document,
            current_private_key_hex,
            current_public_key_id,
            algorithm,
            nonce,
        )?;
        self.submit_with_given_nonce(&new_did_document.id, nonce, &tx)
            .await
    }

    fn update_did_transaction(
        new_did_document: &DidDocument,
        current_private_key_hex: &str,
        current_public_key_id: &str,
        algorithm: SignatureAlgorithm,
        nonce: u64,
    ) -> Result<ChainTransaction> {
        let message = crate::did_rotation::update_did_signing_message(new_did_document, nonce)?;
        let signature_hex = sign_challenge(&message, current_private_key_hex, algorithm)?;
        Self::to_chain_transaction(
            "UpdateDid",
            &UpdateDidTx {
                did_document: new_did_document.clone(),
                signature: hex::decode(signature_hex)?,
                public_key_id: current_public_key_id.to_string(),
                nonce,
            },
        )
    }

    /// Read a DID document from chain state.
    ///
    /// Uses the REST API when one is configured and falls back to the CometBFT
    /// RPC's ABCI store query. Both read the same GroveDB slot, unproven.
    pub async fn get_did_document(&self, did: &str) -> Result<DidDocument> {
        if let Some(api_url) = self.api_url.as_ref() {
            let url = format!("{}/did/{}", api_url.trim_end_matches('/'), did);
            if let Ok(resp) = self.http_client.get(&url).send().await {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    // Response format: {"success": true, "data": {<DidDocument>}}
                    if let Some(data) = body.get("data") {
                        if let Ok(doc) = serde_json::from_value::<DidDocument>(data.clone()) {
                            return Ok(doc);
                        }
                    }
                }
            }
        }
        self.did_document_via_rpc(did).await
    }

    /// Read a DID document via the CometBFT RPC. `abci_query` on
    /// `/store/did/{did}` returns the stored document JSON as base64 in
    /// `result.response.value`.
    async fn did_document_via_rpc(&self, did: &str) -> Result<DidDocument> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "abci_query",
            "params": {
                "path": format!("/store/did/{}", did),
                "data": "",
                "height": "0",
                "prove": false,
            }
        });
        let resp: serde_json::Value = self
            .http_client
            .post(&self.consensus_rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| WillowError::Network(format!("Failed to fetch DID document: {}", e)))?
            .json()
            .await
            .map_err(|e| {
                WillowError::Network(format!("Failed to parse DID document response: {}", e))
            })?;

        let response = &resp["result"]["response"];
        if response["code"].as_u64().unwrap_or(0) != 0 {
            return Err(WillowError::NotFound(format!(
                "DID {}: {}",
                did,
                response["log"].as_str().unwrap_or("not found")
            )));
        }
        let value_b64 = response["value"].as_str().unwrap_or("");
        if value_b64.is_empty() {
            return Err(WillowError::NotFound(format!(
                "DID {} has no document",
                did
            )));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value_b64)
            .map_err(|e| WillowError::Network(format!("DID document base64 decode: {}", e)))?;
        serde_json::from_slice(&bytes).map_err(WillowError::Serialization)
    }

    /// Submit a `ClaimSubgroveIndexing` tx — the indexer's chain-level
    /// announcement that it has locally started indexing `subgrove_id`.
    /// Bumps the subgrove's on-chain `active_indexers` list immediately so
    /// dashboards reflect that work is underway, without waiting for the
    /// first checkpoint or chain-tip submission.
    ///
    /// Idempotent: re-submitting for an already-claimed `(subgrove, indexer)`
    /// pair is a no-op (per the on-chain `add_indexer_to_subgrove` semantics).
    pub async fn claim_subgrove_indexing(
        &self,
        subgrove_id: &str,
        indexer_did: &str,
        indexer_private_key_hex: &str,
        public_key_id: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<String> {
        self.submit_with_nonce(indexer_did, |nonce| {
            // Must match the canonical message format the chain handler verifies.
            let message = format!(
                "ClaimSubgroveIndexing\n{}\n{}\n{}",
                subgrove_id, indexer_did, nonce,
            );
            let signature_hex = sign_challenge(&message, indexer_private_key_hex, algorithm)?;
            Ok(ChainTransaction::ClaimSubgroveIndexing(
                ClaimSubgroveIndexingTx {
                    subgrove_id: subgrove_id.to_string(),
                    indexer_did: indexer_did.to_string(),
                    signature: hex::decode(signature_hex)?,
                    public_key_id: public_key_id.to_string(),
                    nonce,
                },
            ))
        })
        .await
    }

    /// Transfer tokens through consensus
    pub async fn transfer(
        &self,
        from_did: &str,
        to_did: &str,
        amount: u128,
        memo: Option<String>,
        private_key_hex: &str,
        public_key_id: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<String> {
        self.submit_with_nonce(from_did, |nonce| {
            let transfer_message = format!(
                "Transfer\nFrom: {}\nTo: {}\nAmount: {}\nMemo: {}\nNonce: {}",
                from_did,
                to_did,
                amount,
                memo.as_deref().unwrap_or(""),
                nonce
            );
            let signature_hex = sign_challenge(&transfer_message, private_key_hex, algorithm)?;
            Ok(ChainTransaction::Transfer(TransferTx {
                from_did: from_did.to_string(),
                to_did: to_did.to_string(),
                amount,
                memo,
                signature: hex::decode(signature_hex)?,
                public_key_id: public_key_id.to_string(),
                nonce,
            }))
        })
        .await
    }

    /// Submit a raw JSON transaction to CometBFT.
    ///
    /// This is a public wrapper around submit_transaction for CLI/external use. Its nonce is the
    /// caller's: it neither takes one nor settles one in the client's tracker.
    pub async fn submit_raw_transaction(&self, transaction: serde_json::Value) -> Result<String> {
        let tx_json = serde_json::to_string(&transaction)?;
        self.submit_transaction(&tx_json).await
    }

    /// Serialize a transaction variant for submission.
    ///
    /// Uses `serde_json::to_string` directly (not `json!()` or `to_value()`)
    /// to correctly handle u128 fields (token amounts, funding).
    pub fn serialize_tx<T: Serialize>(variant_name: &str, tx: &T) -> Result<String> {
        let inner = serde_json::to_string(tx)?;
        Ok(format!(r#"{{"{}":{}}}"#, variant_name, inner))
    }

    /// Submit a pre-serialized transaction JSON string to CometBFT. Its nonce is the caller's:
    /// it neither takes one nor settles one in the client's tracker.
    pub async fn submit_transaction_json(&self, tx_json: &str) -> Result<String> {
        self.submit_transaction(tx_json).await
    }

    async fn submit_transaction(&self, tx_json: &str) -> Result<String> {
        // Convert JSON-encoded tx to the bincode wire format the validator expects.
        let tx: ChainTransaction =
            serde_json::from_str(tx_json).map_err(WillowError::Serialization)?;
        self.broadcast(&tx).await
    }

    /// Broadcast `tx` to CometBFT as the bincode the validator decodes, so the node reads the
    /// exact values the transaction was signed over.
    pub(crate) async fn broadcast(&self, tx: &ChainTransaction) -> Result<String> {
        match self.submit_bytes(tx).await? {
            Submission::Accepted(hash) => Ok(hash),
            Submission::Refused { code, log } => Err(Self::refused(code, &log, None)),
            Submission::Unknown(e) => Err(e),
        }
    }

    /// Take a nonce for `did`, build the signed transaction under it with `build`, and submit
    /// it, settling the nonce by the outcome. A build that fails gives the nonce back.
    pub(crate) async fn submit_with_nonce<F>(&self, did: &str, build: F) -> Result<String>
    where
        F: FnOnce(u64) -> Result<ChainTransaction>,
    {
        let nonce = self.get_next_nonce(did).await?;
        let tx = match build(nonce) {
            Ok(tx) => tx,
            Err(e) => {
                self.nonces.release(did, nonce);
                return Err(e);
            }
        };
        self.submit_under(did, nonce, &tx).await
    }

    /// Submit `tx`, signed by `did` under a nonce the caller chose, holding the nonce in the
    /// tracker and settling it by the outcome.
    pub(crate) async fn submit_with_given_nonce(
        &self,
        did: &str,
        nonce: u64,
        tx: &ChainTransaction,
    ) -> Result<String> {
        self.nonces.hold(did, nonce);
        self.submit_under(did, nonce, tx).await
    }

    async fn submit_under(&self, did: &str, nonce: u64, tx: &ChainTransaction) -> Result<String> {
        let tx_bytes = match Self::encode(tx) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.nonces.release(did, nonce);
                return Err(e);
            }
        };
        let submission = SignedSubmission {
            did: did.to_string(),
            nonce,
            tx_hash: hex::encode_upper(Sha256::digest(&tx_bytes)),
            tx_bytes,
        };
        self.send_signed(submission, true).await
    }

    /// Send a signed transaction again, the same bytes under the same nonce: the retry of a write
    /// whose outcome is unknown ([`WillowError::SubmissionUnknown`] carries the submission) or
    /// that never landed. Whichever attempt lands first spends the nonce and the other is
    /// refused, so the write runs at most once. CometBFT answers bytes its mempool already holds
    /// with "tx already exists in cache", which counts as accepted: the transaction's hash is
    /// returned. Signing the write again instead takes a new nonce, and both can land.
    ///
    /// The nonce is held while the transaction is in flight and settled by the answer, as for a
    /// new write; an unknown outcome is [`WillowError::SubmissionUnknown`] again, and a
    /// rebroadcast that can't reach the node keeps the nonce held, since the earlier attempt may
    /// still land.
    pub async fn rebroadcast(&self, submission: &SignedSubmission) -> Result<String> {
        self.nonces.hold(&submission.did, submission.nonce);
        self.send_signed(submission.clone(), false).await
    }

    /// Broadcast `submission` and settle its nonce by the answer. When nothing was sent, a new
    /// write (`release_unsent`) gives its nonce back; a rebroadcast doesn't.
    async fn send_signed(
        &self,
        submission: SignedSubmission,
        release_unsent: bool,
    ) -> Result<String> {
        let (did, nonce) = (submission.did.as_str(), submission.nonce);
        let answer = match self.send_bytes(&submission.tx_bytes).await {
            Ok(answer) => answer,
            Err(e) => {
                // Nothing was sent.
                if release_unsent {
                    self.nonces.release(did, nonce);
                }
                return Err(e);
            }
        };
        match answer {
            Submission::Accepted(hash) => {
                self.nonces.settle(did, nonce, NonceOutcome::Accepted);
                Ok(hash)
            }
            Submission::Refused { code, log } => {
                let outcome = refusal_outcome(&log, nonce);
                self.nonces.settle(did, nonce, outcome);
                Err(Self::refused(code, &log, Some(outcome)))
            }
            Submission::Unknown(e) => {
                self.nonces.settle(did, nonce, NonceOutcome::Unknown);
                Err(WillowError::SubmissionUnknown {
                    message: e.to_string(),
                    submission: Box::new(submission),
                })
            }
        }
    }

    fn refused(code: u32, log: &str, outcome: Option<NonceOutcome>) -> WillowError {
        let note = match outcome {
            Some(NonceOutcome::Used) => {
                "; its nonce is used: a write refused this way may be one whose earlier attempt \
                 landed, so read what it wrote before signing it again under a fresh nonce"
            }
            Some(NonceOutcome::Held) => {
                "; a pending transaction holds its nonce: it is not given back until that one \
                 lands or its hold lapses"
            }
            _ => "",
        };
        WillowError::Custom(format!(
            "Transaction failed: {} (code: {}){}",
            log, code, note
        ))
    }

    /// The bincode the validator decodes `tx` from.
    fn encode(tx: &ChainTransaction) -> Result<Vec<u8>> {
        bincode::serialize(tx)
            .map_err(|e| WillowError::Custom(format!("bincode serialize transaction: {}", e)))
    }

    /// Send `tx` to CometBFT's `broadcast_tx_sync`. `Err` only when nothing was sent.
    async fn submit_bytes(&self, tx: &ChainTransaction) -> Result<Submission> {
        self.send_bytes(&Self::encode(tx)?).await
    }

    /// Send `tx_bytes` to CometBFT's `broadcast_tx_sync`. `Err` only when nothing was sent.
    async fn send_bytes(&self, tx_bytes: &[u8]) -> Result<Submission> {
        let tx_base64 = base64::engine::general_purpose::STANDARD.encode(tx_bytes);

        let rpc_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "broadcast_tx_sync",
            "params": {
                "tx": tx_base64
            }
        });

        let response = match self
            .http_client
            .post(&self.consensus_rpc_url)
            .json(&rpc_request)
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) if e.is_connect() || e.is_builder() => return Err(e.into()),
            Err(e) => return Ok(Submission::Unknown(e.into())),
        };
        let response_text = match response.text().await {
            Ok(text) => text,
            Err(e) => return Ok(Submission::Unknown(e.into())),
        };
        let rpc_response: CometBftResponse = match serde_json::from_str(&response_text) {
            Ok(r) => r,
            Err(e) => return Ok(Submission::Unknown(WillowError::Serialization(e))),
        };

        if let Some(error) = rpc_response.error {
            let detail = error.data.clone().unwrap_or_default();
            // CometBFT already holds these exact bytes (pending, or committed recently): the
            // copy CheckTx admitted is this transaction.
            if detail.trim_end().ends_with("tx already exists in cache")
                || error
                    .message
                    .trim_end()
                    .ends_with("tx already exists in cache")
            {
                return Ok(Submission::Accepted(hex::encode_upper(Sha256::digest(
                    tx_bytes,
                ))));
            }
            return Ok(Submission::Unknown(WillowError::Custom(format!(
                "CometBFT error: {} ({}){}",
                error.message,
                error.code,
                error
                    .data
                    .as_ref()
                    .map(|d| format!(": {}", d))
                    .unwrap_or_default()
            ))));
        }

        match rpc_response.result {
            Some(result) if result.code != 0 => Ok(Submission::Refused {
                code: result.code,
                log: result.log,
            }),
            Some(result) => Ok(Submission::Accepted(result.hash)),
            None => Ok(Submission::Unknown(WillowError::Custom(
                "No result in response".to_string(),
            ))),
        }
    }

    /// Convert a hex tx hash to base64 for CometBFT's JSON-RPC `tx` method.
    ///
    /// CometBFT's HTTP URI API accepts `0x`-prefixed hex, but the JSON-RPC
    /// `tx` method expects the hash as base64-encoded bytes.
    fn tx_hash_to_base64(tx_hash: &str) -> Result<String> {
        let bare = tx_hash.strip_prefix("0x").unwrap_or(tx_hash);
        let bytes = hex::decode(bare)
            .map_err(|e| WillowError::Custom(format!("Invalid tx hash hex: {}", e)))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
    }

    /// Poll until the tx is in a block, returning what the block said about it.
    ///
    /// `broadcast_tx_sync` only reports CheckTx, so a tx can be accepted into
    /// the mempool and still fail during execution. `Ok(None)` means the tx was
    /// still not in a block after `max_attempts`.
    pub async fn wait_for_tx_outcome(
        &self,
        tx_hash: &str,
        max_attempts: u32,
    ) -> Result<Option<TxOutcome>> {
        let hash = Self::tx_hash_to_base64(tx_hash)?;
        for _ in 0..max_attempts {
            let query_request = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tx",
                "params": {
                    "hash": hash,
                    "prove": false
                }
            });

            if let Ok(response) = self
                .http_client
                .post(&self.consensus_rpc_url)
                .json(&query_request)
                .send()
                .await
            {
                if let Ok(body) = response.json::<serde_json::Value>().await {
                    if let Some(outcome) = Self::parse_tx_outcome(&body) {
                        return Ok(Some(outcome));
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }

        Ok(None)
    }

    /// Pull a [`TxOutcome`] out of a CometBFT `tx` response.
    ///
    /// A tx that is not in a block yet answers with an error or a null result,
    /// so only a parseable height counts as inclusion — otherwise a pending tx
    /// would read as "height 0, code 0", i.e. a success that never happened.
    /// CometBFT encodes height as a string, and omits `code` when it is 0.
    fn parse_tx_outcome(body: &serde_json::Value) -> Option<TxOutcome> {
        let result = &body["result"];
        let height = result["height"]
            .as_str()
            .and_then(|h| h.parse::<i64>().ok())
            .or_else(|| result["height"].as_i64())?;
        Some(TxOutcome {
            height,
            code: result["tx_result"]["code"].as_u64().unwrap_or(0) as u32,
            log: result["tx_result"]["log"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        })
    }

    /// Wait for transaction to be included in a block
    pub async fn wait_for_transaction(&self, tx_hash: &str, max_attempts: u32) -> Result<bool> {
        let hash = Self::tx_hash_to_base64(tx_hash)?;
        for _ in 0..max_attempts {
            // Query transaction status
            let query_request = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tx",
                "params": {
                    "hash": hash,
                    "prove": false
                }
            });

            if let Ok(response) = self
                .http_client
                .post(&self.consensus_rpc_url)
                .json(&query_request)
                .send()
                .await
            {
                if let Ok(response_text) = response.text().await {
                    if let Ok(rpc_response) =
                        serde_json::from_str::<serde_json::Value>(&response_text)
                    {
                        if rpc_response.get("result").is_some() {
                            return Ok(true);
                        }
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }

        Ok(false)
    }

    /// Register a DataStorage subgrove using SigningKey.
    ///
    /// Takes the nonce, then signs [`signed_messages::register_subgrove`] over the transaction
    /// it sends (`request.nonce` and `request.signature` are ignored). Every field is sent
    /// explicitly: no read pricing, privacy, TEE requirement, or template, a confirmation depth
    /// of 0, and no cryptographic completeness. A registration the node's registration rules
    /// refuse ([`signed_messages::check_register_subgrove`]) is refused before signing.
    pub async fn register_subgrove(
        &self,
        request: RegisterSubgroveRequest,
        signing_key: &SigningKey,
    ) -> Result<String> {
        let schema = match &request.schema {
            Some(schema) => serde_json::to_string(schema)?,
            None => "{}".to_string(),
        };
        let register_tx = RegisterSubgroveTx {
            subgrove_id: request.subgrove_id,
            name: request.name.clone(),
            description: request.description,
            schema,
            owner_did: request.owner_did,
            admins: request.admins,
            initial_funding: request.initial_funding,
            checkpoint_verification: Default::default(),
            mode: SubgroveMode::DataStorage {
                name: request.name,
                writers: request.writers,
                free_readers: request.readers,
                read_pricing: None,
            },
            privacy: None,
            initial_owner_key_grant: None,
            template_config: None,
            confirmation_depth: 0,
            signature: vec![],
            public_key_id: request.public_key_id,
            nonce: 0,
            cryptographic_completeness: false,
        };
        self.sign_and_register(register_tx, signing_key).await
    }

    /// Register a file storage subgrove using SigningKey.
    ///
    /// File storage subgroves store files with chunk-level Merkle verification
    /// via dedicated storage nodes. Signed like [`Self::register_subgrove`], with no admins,
    /// description, read pricing, or retention period.
    pub async fn register_file_subgrove(
        &self,
        subgrove_id: &str,
        name: &str,
        owner_did: &str,
        writers: Vec<String>,
        readers: Vec<String>,
        max_file_size: u64,
        replication_factor: u8,
        public_key_id: &str,
        signing_key: &SigningKey,
        initial_funding: Option<u128>,
    ) -> Result<String> {
        let register_tx = RegisterSubgroveTx {
            subgrove_id: subgrove_id.to_string(),
            name: name.to_string(),
            description: String::new(),
            schema: "{}".to_string(),
            owner_did: owner_did.to_string(),
            admins: vec![],
            initial_funding,
            checkpoint_verification: Default::default(),
            mode: SubgroveMode::FileStorage {
                name: name.to_string(),
                max_file_size,
                replication_factor,
                writers,
                free_readers: readers,
                read_pricing: None,
                retention_period: 0,
            },
            privacy: None,
            initial_owner_key_grant: None,
            template_config: None,
            confirmation_depth: 0,
            signature: vec![],
            public_key_id: public_key_id.to_string(),
            nonce: 0,
            cryptographic_completeness: false,
        };
        self.sign_and_register(register_tx, signing_key).await
    }

    /// Check `tx` against the registration rules, take its owner's nonce, sign
    /// [`signed_messages::register_subgrove`] over it, and broadcast exactly the transaction whose
    /// bincode the `Config` line hashes.
    async fn sign_and_register(
        &self,
        tx: RegisterSubgroveTx,
        signing_key: &SigningKey,
    ) -> Result<String> {
        signed_messages::check_register_subgrove(&tx)?;
        let owner = tx.owner_did.clone();
        self.submit_with_nonce(&owner, |nonce| {
            let mut tx = RegisterSubgroveTx { nonce, ..tx };
            let message = signed_messages::register_subgrove(&tx)?;
            tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
            Ok(ChainTransaction::RegisterSubgrove(tx))
        })
        .await
    }

    /// Register a blockchain indexing subgrove from a definition file.
    ///
    /// Builds the transaction with
    /// [`SubgroveDefinition::register_transaction`](crate::subgrove_config::SubgroveDefinition::register_transaction),
    /// signs [`signed_messages::register_subgrove`] over it with the nonce taken here, and
    /// submits it. This is the simplest way to deploy a predefined subgrove.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use willow_sdk::subgrove_config::SubgroveDefinition;
    /// use willow_sdk::consensus::ConsensusClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = ConsensusClient::new("http://localhost:26657");
    /// let def = SubgroveDefinition::load("subgrove_definitions/ethereum/aave-v3.toml")?;
    ///
    /// let key_bytes = [0u8; 32];
    /// let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    /// let tx_hash = client.register_blockchain_subgrove(
    ///     &def,
    ///     "did:willow:owner",
    ///     "did:willow:owner#key-1",
    ///     &signing_key,
    ///     None, // initial funding
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn register_blockchain_subgrove(
        &self,
        definition: &crate::subgrove_config::SubgroveDefinition,
        owner_did: &str,
        public_key_id: &str,
        signing_key: &SigningKey,
        initial_funding: Option<u128>,
    ) -> Result<String> {
        let register_tx =
            definition.register_transaction(owner_did, public_key_id, 0, initial_funding)?;
        self.sign_and_register(register_tx, signing_key).await
    }

    /// Store data using SigningKey.
    ///
    /// `request.data` is sent as its JSON text, and the transaction is signed over
    /// [`signed_messages::store_data`] with the nonce taken here (`request.nonce` and
    /// `request.signature` are ignored). The node stores only a JSON object: other data is
    /// refused ([`WillowError::Validation`]) before a nonce is taken.
    pub async fn store_data(
        &self,
        request: StoreDataRequest,
        signing_key: &SigningKey,
    ) -> Result<String> {
        if !request.data.is_object() {
            return Err(WillowError::Validation(
                "StoreData's data must be a JSON object; the node refuses any other".to_string(),
            ));
        }
        let data = serde_json::to_vec(&request.data)?;
        let owner = request.owner_did.clone();
        self.submit_with_nonce(&owner, |nonce| {
            let mut tx = StoreDataTx {
                subgrove_id: request.subgrove_id,
                key: request.key,
                data,
                owner_did: request.owner_did,
                signature: vec![],
                public_key_id: request.public_key_id,
                nonce,
            };
            let message = signed_messages::store_data(&tx)?;
            tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
            Ok(ChainTransaction::StoreData(tx))
        })
        .await
    }

    /// Delete data using SigningKey, signed over [`signed_messages::delete_data`] with the
    /// nonce taken here.
    pub async fn delete_data(
        &self,
        subgrove_id: &str,
        key: &str,
        owner_did: &str,
        public_key_id: &str,
        signing_key: &SigningKey,
    ) -> Result<String> {
        self.submit_with_nonce(owner_did, |nonce| {
            let mut tx = DeleteDataTx {
                subgrove_id: subgrove_id.to_string(),
                key: key.to_string(),
                owner_did: owner_did.to_string(),
                signature: vec![],
                public_key_id: public_key_id.to_string(),
                nonce,
            };
            let message = signed_messages::delete_data(&tx)?;
            tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
            Ok(ChainTransaction::DeleteData(tx))
        })
        .await
    }

    /// Fund a subgrove using SigningKey, with the nonce taken here (`request.nonce` and
    /// `request.signature` are ignored).
    pub async fn fund_subgrove(
        &self,
        request: crate::types::FundSubgroveRequest,
        signing_key: &SigningKey,
    ) -> Result<String> {
        let from = request.from_did.clone();
        self.submit_with_nonce(&from, |nonce| {
            let signing_payload = format!(
                "FundSubgrove\nSubgrove: {}\nAmount: {}\nFrom: {}\nNonce: {}",
                request.subgrove_id, request.amount, request.from_did, nonce
            );
            let signature = signing_key.sign(signing_payload.as_bytes());
            Ok(ChainTransaction::FundSubgrove(FundSubgroveTx {
                subgrove_id: request.subgrove_id,
                amount: request.amount,
                from_did: request.from_did,
                signature: signature.to_bytes().to_vec(),
                public_key_id: request.public_key_id,
                nonce,
            }))
        })
        .await
    }

    /// Deregister (delete) a subgrove using SigningKey, with the nonce taken here.
    ///
    /// Remaining subgrove funding balance is refunded to the owner.
    pub async fn deregister_subgrove(
        &self,
        request: crate::types::DeregisterSubgroveRequest,
        signing_key: &SigningKey,
    ) -> Result<String> {
        let owner = request.owner_did.clone();
        self.submit_with_nonce(&owner, |nonce| {
            let signing_payload = format!(
                "DeregisterSubgrove:{}:{}:{}",
                request.subgrove_id, request.owner_did, nonce
            );
            let signature = signing_key.sign(signing_payload.as_bytes());
            Ok(ChainTransaction::DeregisterSubgrove(DeregisterSubgroveTx {
                subgrove_id: request.subgrove_id,
                owner_did: request.owner_did,
                signature: signature.to_bytes().to_vec(),
                public_key_id: request.public_key_id,
                nonce,
            }))
        })
        .await
    }

    /// Get transaction result
    pub async fn get_transaction(&self, tx_hash: &str) -> Result<TransactionResult> {
        let hash = Self::tx_hash_to_base64(tx_hash)?;
        let query_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tx",
            "params": {
                "hash": hash,
                "prove": false
            }
        });

        let response = self
            .http_client
            .post(&self.consensus_rpc_url)
            .json(&query_request)
            .send()
            .await?;

        let response_text = response.text().await?;
        let rpc_response: serde_json::Value =
            serde_json::from_str(&response_text).map_err(|e| WillowError::Serialization(e))?;

        if let Some(result) = rpc_response.get("result") {
            if let Some(tx_result) = result.get("tx_result") {
                let code = tx_result.get("code").and_then(|c| c.as_u64()).unwrap_or(1) as u32;
                let log = tx_result
                    .get("log")
                    .and_then(|l| l.as_str())
                    .unwrap_or("Unknown error")
                    .to_string();

                return Ok(TransactionResult { code, log });
            }
        }

        Err(WillowError::Custom("Transaction not found".to_string()))
    }
}

/// Transaction result
#[derive(Debug, Clone)]
pub struct TransactionResult {
    pub code: u32,
    pub log: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // ConsensusClient Creation Tests
    // ========================================================================

    #[test]
    fn test_consensus_client_creation() {
        let client = ConsensusClient::new("http://localhost:26657");
        assert_eq!(client.consensus_rpc_url, "http://localhost:26657");
    }

    // ========================================================================
    // Transaction Inclusion Tests
    // ========================================================================

    #[test]
    fn parse_tx_outcome_reads_height_and_code() {
        let body = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {
                "hash": "ABC",
                "height": "12345",
                "tx_result": { "code": 0, "log": "DID updated: did:willow:validator1" }
            }
        });
        let outcome = ConsensusClient::parse_tx_outcome(&body).unwrap();
        assert_eq!(outcome.height, 12345);
        assert_eq!(outcome.code, 0);
        assert_eq!(outcome.log, "DID updated: did:willow:validator1");
    }

    #[test]
    fn parse_tx_outcome_reads_a_failed_execution() {
        let body = json!({
            "result": {
                "height": "77",
                "tx_result": { "code": 1, "log": "Invalid signature for UpdateDid" }
            }
        });
        let outcome = ConsensusClient::parse_tx_outcome(&body).unwrap();
        assert_eq!(outcome.code, 1);
        assert_eq!(outcome.log, "Invalid signature for UpdateDid");
    }

    #[test]
    fn parse_tx_outcome_does_not_read_a_pending_tx_as_success() {
        // "tx not found" — an error, or a null result, depending on the node.
        let not_found = json!({
            "jsonrpc": "2.0", "id": 1,
            "error": { "code": -32603, "message": "Internal error", "data": "tx not found" }
        });
        assert!(ConsensusClient::parse_tx_outcome(&not_found).is_none());
        assert!(ConsensusClient::parse_tx_outcome(&json!({ "result": null })).is_none());
        assert!(ConsensusClient::parse_tx_outcome(&json!({})).is_none());
    }

    // ========================================================================
    // Transaction Type Serialization Tests
    // ========================================================================

    #[test]
    fn test_register_did_tx_serialization() {
        let tx = RegisterDidTx {
            did_document: DidDocument {
                id: "did:willow:test".to_string(),
                public_keys: vec![],
                authentication: vec![],
                service: vec![],
                created: 1234567890,
                updated: 1234567890,
                proof: None,
            },
            signature: vec![1, 2, 3],
            public_key_id: "did:willow:test#key-1".to_string(),
            nonce: 1,
        };

        let json = serde_json::to_string(&tx).unwrap();
        let deserialized: RegisterDidTx = serde_json::from_str(&json).unwrap();

        assert_eq!(tx.did_document.id, deserialized.did_document.id);
        assert_eq!(tx.signature, deserialized.signature);
        assert_eq!(tx.nonce, deserialized.nonce);
    }

    #[test]
    fn test_register_subgrove_tx_serialization() {
        let tx = RegisterSubgroveTx {
            subgrove_id: "test-subgrove".to_string(),
            name: "Test Subgrove".to_string(),
            description: "A test subgrove".to_string(),
            schema: r#"{"type":"object"}"#.to_string(),
            owner_did: "did:willow:owner".to_string(),
            admins: vec![],
            initial_funding: None,
            mode: SubgroveMode::DataStorage {
                name: "Test Subgrove".to_string(),
                writers: vec!["did:willow:writer".to_string()],
                free_readers: vec!["did:willow:reader".to_string()],
                read_pricing: None,
            },
            checkpoint_verification: Default::default(),
            privacy: None,
            initial_owner_key_grant: None,
            template_config: None,
            confirmation_depth: 0,
            signature: vec![7, 8, 9],
            public_key_id: "did:willow:owner#key-1".to_string(),
            nonce: 3,
            cryptographic_completeness: true,
        };

        let json = serde_json::to_string(&tx).unwrap();
        let deserialized: RegisterSubgroveTx = serde_json::from_str(&json).unwrap();

        assert_eq!(tx.subgrove_id, deserialized.subgrove_id);
        assert_eq!(tx.schema, deserialized.schema);
        assert!(deserialized.cryptographic_completeness);
    }

    #[test]
    fn test_transfer_tx_serialization() {
        let tx = TransferTx {
            from_did: "did:willow:sender".to_string(),
            to_did: "did:willow:receiver".to_string(),
            amount: 1000000,
            memo: Some("Test transfer".to_string()),
            signature: vec![10, 11, 12],
            public_key_id: "did:willow:sender#key-1".to_string(),
            nonce: 4,
        };

        let json = serde_json::to_string(&tx).unwrap();
        let deserialized: TransferTx = serde_json::from_str(&json).unwrap();

        assert_eq!(tx.from_did, deserialized.from_did);
        assert_eq!(tx.to_did, deserialized.to_did);
        assert_eq!(tx.amount, deserialized.amount);
        assert_eq!(tx.memo, deserialized.memo);
    }

    #[test]
    fn test_transfer_tx_without_memo() {
        let tx = TransferTx {
            from_did: "did:willow:sender".to_string(),
            to_did: "did:willow:receiver".to_string(),
            amount: 500,
            memo: None,
            signature: vec![],
            public_key_id: "did:willow:sender#key-1".to_string(),
            nonce: 5,
        };

        let json = serde_json::to_string(&tx).unwrap();
        let deserialized: TransferTx = serde_json::from_str(&json).unwrap();

        assert!(deserialized.memo.is_none());
    }

    // ========================================================================
    // CometBFT Response Type Tests
    // ========================================================================

    #[test]
    fn test_cometbft_response_success() {
        let json_str = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "code": 0,
                "data": "",
                "log": "success",
                "hash": "ABCD1234"
            }
        }"#;

        let response: CometBftResponse = serde_json::from_str(json_str).unwrap();
        assert!(response.result.is_some());
        assert!(response.error.is_none());

        let result = response.result.unwrap();
        assert_eq!(result.code, 0);
        assert_eq!(result.hash, "ABCD1234");
    }

    #[test]
    fn test_cometbft_response_error() {
        let json_str = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32000,
                "message": "Transaction failed",
                "data": "invalid signature"
            }
        }"#;

        let response: CometBftResponse = serde_json::from_str(json_str).unwrap();
        assert!(response.result.is_none());
        assert!(response.error.is_some());

        let error = response.error.unwrap();
        assert_eq!(error.code, -32000);
        assert_eq!(error.message, "Transaction failed");
    }

    // ========================================================================
    // Transaction Result Tests
    // ========================================================================

    #[test]
    fn test_transaction_result() {
        let result = TransactionResult {
            code: 0,
            log: "Transaction succeeded".to_string(),
        };

        assert_eq!(result.code, 0);
        assert_eq!(result.log, "Transaction succeeded");
    }

    #[test]
    fn test_transaction_result_failure() {
        let result = TransactionResult {
            code: 1,
            log: "Insufficient funds".to_string(),
        };

        assert_eq!(result.code, 1);
        assert!(result.log.contains("Insufficient"));
    }

    #[tokio::test]
    async fn store_data_refuses_data_that_is_not_a_json_object_before_taking_a_nonce() {
        let server = wiremock::MockServer::start().await;
        let client = ConsensusClient::new(&server.uri());
        let key = SigningKey::from_bytes(&[7; 32]);
        for data in [
            json!([1, 2]),
            json!("text"),
            json!(3),
            json!(null),
            json!(true),
        ] {
            let request = StoreDataRequest {
                subgrove_id: "sg".into(),
                key: "k".into(),
                data: data.clone(),
                owner_did: "did:willow:a".into(),
                signature: vec![],
                public_key_id: "did:willow:a#key-1".into(),
                nonce: 0,
            };
            let err = client.store_data(request, &key).await.unwrap_err();
            assert!(matches!(err, WillowError::Validation(_)), "{data}: {err}");
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// The clock is paused, so it runs ahead to the next timer whenever the test waits: a
    /// request with no timeout waits out the 600 s below, one with a timeout fails first.
    #[tokio::test(start_paused = true)]
    async fn a_node_that_never_answers_times_out() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(3600)),
            )
            .mount(&server)
            .await;
        let client = ConsensusClient::new(&server.uri());
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            client.get_next_nonce("did:willow:a"),
        )
        .await;
        assert!(
            matches!(outcome, Ok(Err(WillowError::Network(_)))),
            "{outcome:?}"
        );
    }

    /// A write whose outcome is unknown carries its DID, nonce, and the exact bytes it sent;
    /// `rebroadcast` sends those bytes again, which CometBFT answers as already held.
    #[tokio::test]
    async fn an_unknown_outcome_carries_the_signed_bytes_and_rebroadcast_resends_them() {
        use wiremock::matchers::{body_partial_json, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let state = [&5u64.to_be_bytes()[..], &[0, 0, 0]].concat();
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "abci_query"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {"response": {
                    "code": 0,
                    "value": base64::engine::general_purpose::STANDARD.encode(state)
                }}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "broadcast_tx_sync"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32603, "message": "Internal error", "data": "timed out waiting for tx"}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "broadcast_tx_sync"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32603, "message": "Internal error", "data": "tx already exists in cache"}
            })))
            .mount(&server)
            .await;
        let client = ConsensusClient::new(&server.uri());
        let did = "did:willow:a";
        let sent = |requests: Vec<wiremock::Request>| -> Vec<Vec<u8>> {
            requests
                .iter()
                .filter_map(|r| {
                    let body: serde_json::Value = serde_json::from_slice(&r.body).ok()?;
                    (body["method"] == "broadcast_tx_sync").then(|| {
                        base64::engine::general_purpose::STANDARD
                            .decode(body["params"]["tx"].as_str().unwrap())
                            .unwrap()
                    })
                })
                .collect()
        };

        let err = client
            .transfer(
                did,
                "did:willow:b",
                7,
                None,
                &"03".repeat(32),
                "did:willow:a#key-1",
                SignatureAlgorithm::Ed25519,
            )
            .await
            .unwrap_err();
        let WillowError::SubmissionUnknown { submission, .. } = err else {
            panic!("expected an unknown outcome, got {err:?}");
        };
        assert_eq!((submission.did.as_str(), submission.nonce), (did, 6));
        assert_eq!(
            submission.tx_hash,
            hex::encode_upper(Sha256::digest(&submission.tx_bytes))
        );
        assert_eq!(
            sent(server.received_requests().await.unwrap()),
            vec![submission.tx_bytes.clone()]
        );
        assert!(client.nonce_tracker().is_held(did, 6));

        let hash = client.rebroadcast(&submission).await.unwrap();
        assert_eq!(hash, submission.tx_hash);
        assert_eq!(
            sent(server.received_requests().await.unwrap()),
            vec![submission.tx_bytes.clone(), submission.tx_bytes.clone()]
        );
        assert!(client.nonce_tracker().is_held(did, 6));
    }
}
