//! Privacy operations for private subgroves.
//!
//! This module provides client-side operations for managing private subgroves:
//!
//! - **Key grant management** — grant, revoke, and rotate encryption keys
//! - **Key grant queries** — retrieve grants and proofs via the REST API
//!
//! # Example
//!
//! ```rust,no_run
//! use willow_sdk::WillowClient;
//! use willow_sdk::privacy::{PrivacyConfig, CommitmentFrequency};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = WillowClient::new("http://localhost:3031").await?;
//!
//! // Register a private subgrove
//! let privacy = PrivacyConfig {
//!     allowed_indexers: Some(vec!["did:willow:my-indexer".to_string()]),
//!     commitment_frequency: CommitmentFrequency::EveryNBlocks(10),
//! };
//! # Ok(())
//! # }
//! ```

use crate::errors::{Result, WillowError};
use crate::signed_messages::{self, GrantSubgroveKeyTx, RevokeSubgroveKeyTx, RotateSubgroveKeyTx};
use crate::types::ApiResponse;
use crate::WillowClient;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use willow_types::consensus::transactions::Transaction;

/// Privacy configuration for a private subgrove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Optional whitelist of indexer DIDs allowed to index this subgrove.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_indexers: Option<Vec<String>>,
    /// How often the provider must commit state roots to consensus.
    pub commitment_frequency: CommitmentFrequency,
}

/// How often the provider must publish state root commitments on-chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CommitmentFrequency {
    /// Commit after every write/block update.
    EveryUpdate,
    /// Commit every N blocks processed.
    EveryNBlocks(u64),
    /// Commit at least every N seconds.
    EveryNSeconds(u64),
    /// No on-chain commitments.
    Never,
}

/// An encrypted key grant for a subgrove: the chain's own type, so a grant signs and encodes
/// exactly as the node reads it.
pub use willow_types::storage::EncryptedKeyGrant;

/// Privacy-related operations for private subgroves.
pub struct PrivacyOperations {
    client: WillowClient,
}

impl PrivacyOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Get the encryption key grant for the authenticated DID.
    ///
    /// Returns the encrypted key grant that allows this DID to decrypt
    /// the subgrove's data.
    pub async fn get_my_key_grant(&self, subgrove_id: &str) -> Result<EncryptedKeyGrant> {
        let did = self
            .client
            .get_did()
            .ok_or_else(|| WillowError::Authentication("Identity not set".into()))?;

        let response: ApiResponse<EncryptedKeyGrant> = self
            .client
            .request(
                "GET",
                &format!("/key-grants/{}/{}", subgrove_id, did),
                None::<&()>,
                true,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound("Key grant not found".into()))
    }

    /// List all grantee DIDs for a subgrove.
    ///
    /// Only the subgrove owner or admin can call this.
    pub async fn list_key_grantees(&self, subgrove_id: &str) -> Result<Vec<String>> {
        let response: ApiResponse<Vec<String>> = self
            .client
            .request(
                "GET",
                &format!("/key-grants/{}", subgrove_id),
                None::<&()>,
                true,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound("No grantees found".into()))
    }

    /// Get the GroveDB Merkle proof for a key grant.
    ///
    /// Public endpoint — proofs are non-sensitive.
    pub async fn get_key_grant_proof(
        &self,
        subgrove_id: &str,
        did: &str,
    ) -> Result<serde_json::Value> {
        let response: ApiResponse<serde_json::Value> = self
            .client
            .request(
                "GET",
                &format!("/proof/key-grant/{}/{}", subgrove_id, did),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound("Proof not found".into()))
    }

    /// Submit a GrantSubgroveKey transaction via consensus.
    ///
    /// Grants the specified DID access to the subgrove's encryption key. Signed over
    /// [`signed_messages::grant_subgrove_key`], which binds every field of the grant and `nonce`;
    /// a grantee that isn't a DID is refused before signing, and gives `nonce` back to the client's
    /// nonce tracker. Once sent, `nonce` is held for this write in the tracker and settled by its
    /// outcome; take one with [`crate::consensus::ConsensusClient::get_next_nonce`].
    pub async fn grant_subgrove_key(
        &self,
        subgrove_id: &str,
        grant: EncryptedKeyGrant,
        sender_did: &str,
        signing_key: &SigningKey,
        public_key_id: &str,
        nonce: u64,
    ) -> Result<String> {
        let consensus = self.client.require_consensus("grant_subgrove_key")?;
        let mut tx = GrantSubgroveKeyTx {
            subgrove_id: subgrove_id.to_string(),
            encrypted_key_grant: grant,
            sender_did: sender_did.to_string(),
            signature: vec![],
            public_key_id: public_key_id.to_string(),
            nonce,
        };
        let message = given_back(
            consensus,
            sender_did,
            nonce,
            signed_messages::grant_subgrove_key(&tx),
        )?;
        tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
        consensus
            .submit_with_given_nonce(sender_did, nonce, &Transaction::GrantSubgroveKey(tx))
            .await
    }

    /// Submit a RevokeSubgroveKey transaction via consensus.
    ///
    /// Revokes the specified DID's access to the subgrove's encryption key. Signed over
    /// [`signed_messages::revoke_subgrove_key`]; a subgrove ID holding `:`, or a revokee or sender
    /// that isn't a DID, is refused before signing. `nonce` is held and settled as for a grant.
    pub async fn revoke_subgrove_key(
        &self,
        subgrove_id: &str,
        revokee_did: &str,
        sender_did: &str,
        signing_key: &SigningKey,
        public_key_id: &str,
        nonce: u64,
    ) -> Result<String> {
        let consensus = self.client.require_consensus("revoke_subgrove_key")?;
        let mut tx = RevokeSubgroveKeyTx {
            subgrove_id: subgrove_id.to_string(),
            revokee_did: revokee_did.to_string(),
            sender_did: sender_did.to_string(),
            signature: vec![],
            public_key_id: public_key_id.to_string(),
            nonce,
        };
        let message = given_back(
            consensus,
            sender_did,
            nonce,
            signed_messages::revoke_subgrove_key(&tx),
        )?;
        tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
        consensus
            .submit_with_given_nonce(sender_did, nonce, &Transaction::RevokeSubgroveKey(tx))
            .await
    }

    /// Submit a RotateSubgroveKey transaction via consensus.
    ///
    /// Rotates the subgrove encryption key to a new epoch with new grants. Signed over
    /// [`signed_messages::rotate_subgrove_key`], which binds every grant, their count and order,
    /// and `nonce`. No grants, a grant at another key epoch than `new_epoch`, or a grantee that
    /// isn't a DID is refused before signing. `nonce` is held and settled as for a grant.
    pub async fn rotate_subgrove_key(
        &self,
        subgrove_id: &str,
        new_epoch: u32,
        new_grants: Vec<EncryptedKeyGrant>,
        sender_did: &str,
        signing_key: &SigningKey,
        public_key_id: &str,
        nonce: u64,
    ) -> Result<String> {
        let consensus = self.client.require_consensus("rotate_subgrove_key")?;
        let mut tx = RotateSubgroveKeyTx {
            subgrove_id: subgrove_id.to_string(),
            new_epoch,
            new_grants,
            sender_did: sender_did.to_string(),
            signature: vec![],
            public_key_id: public_key_id.to_string(),
            nonce,
        };
        let message = given_back(
            consensus,
            sender_did,
            nonce,
            signed_messages::rotate_subgrove_key(&tx),
        )?;
        tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
        consensus
            .submit_with_given_nonce(sender_did, nonce, &Transaction::RotateSubgroveKey(tx))
            .await
    }
}

/// `result`, giving `nonce` back to the client's tracker when it is an error: a transaction
/// refused before it is sent leaves its nonce unused.
fn given_back<T>(
    consensus: &crate::consensus::ConsensusClient,
    did: &str,
    nonce: u64,
    result: Result<T>,
) -> Result<T> {
    if result.is_err() {
        consensus.nonce_tracker().release(did, nonce);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A key grant, rotation, or revoke the SDK refuses before sending it gives back the nonce
    /// the caller took for it.
    #[tokio::test]
    async fn a_key_transaction_refused_before_sending_gives_its_nonce_back() {
        let server = MockServer::start().await;
        let state = [&5u64.to_be_bytes()[..], &[0, 0, 0]].concat();
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {"response": {
                    "code": 0,
                    "value": base64::engine::general_purpose::STANDARD.encode(state)
                }}
            })))
            .mount(&server)
            .await;
        let client = WillowClient::builder()
            .api_url(&server.uri())
            .consensus_url(&server.uri())
            .build()
            .await
            .unwrap();
        let did = "did:willow:a";
        let key = SigningKey::from_bytes(&[7; 32]);
        let not_a_did = EncryptedKeyGrant {
            grantee_did: "not-a-did".into(),
            key_epoch: 1,
            grantee_public_key_id: "k".into(),
            ephemeral_public_key: vec![1; 32],
            encrypted_key: vec![2; 56],
            granted_by: did.into(),
            granted_at: 1,
        };
        let consensus = client.consensus();
        let privacy = client.privacy();

        let nonce = consensus.get_next_nonce(did).await.unwrap();
        assert!(privacy
            .grant_subgrove_key("sg", not_a_did.clone(), did, &key, "kid", nonce)
            .await
            .is_err());
        assert!(!consensus.nonce_tracker().is_held(did, nonce), "grant");

        let nonce = consensus.get_next_nonce(did).await.unwrap();
        assert!(privacy
            .rotate_subgrove_key("sg", 1, vec![not_a_did], did, &key, "kid", nonce)
            .await
            .is_err());
        assert!(!consensus.nonce_tracker().is_held(did, nonce), "rotation");

        let nonce = consensus.get_next_nonce(did).await.unwrap();
        assert!(privacy
            .revoke_subgrove_key("sg", "not-a-did", did, &key, "kid", nonce)
            .await
            .is_err());
        assert!(!consensus.nonce_tracker().is_held(did, nonce), "revoke");
    }
}
