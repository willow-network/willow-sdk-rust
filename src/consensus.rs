//! Consensus transaction handling for Willow SDK

use crate::auth::sign_challenge;
use crate::errors::{Result, WillowError};
use crate::types::{DidDocument, RegisterSubgroveRequest, SignatureAlgorithm, StoreDataRequest};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Transaction types for consensus - match the working format exactly
pub type Transaction = serde_json::Value;

/// Register DID transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDidTx {
    pub did_document: DidDocument,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub nonce: u64,
}

pub use willow_types::consensus::indexing_transactions::RetentionWindow;

pub use willow_types::consensus::indexing_transactions::SubgroveMode;
pub use willow_types::consensus::transactions::{
    DeleteDataTx, DeregisterSubgroveTx, FundSubgroveTx, RegisterSubgroveTx, TransferTx,
};

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

/// Consensus client for submitting transactions
pub struct ConsensusClient {
    http_client: Client,
    consensus_rpc_url: String,
    api_url: Option<String>,
}

impl ConsensusClient {
    /// Create a new consensus client
    pub fn new(consensus_rpc_url: &str) -> Self {
        Self {
            http_client: Client::new(),
            consensus_rpc_url: consensus_rpc_url.to_string(),
            api_url: None,
        }
    }

    /// Create a new consensus client with API URL for nonce auto-management
    pub fn new_with_api(consensus_rpc_url: &str, api_url: &str) -> Self {
        Self {
            http_client: Client::new(),
            consensus_rpc_url: consensus_rpc_url.to_string(),
            api_url: Some(api_url.to_string()),
        }
    }

    /// Fetch the next valid nonce for a DID from the API server.
    pub async fn get_next_nonce(&self, did: &str) -> Result<u64> {
        let api_url = self.api_url.as_ref().ok_or_else(|| {
            WillowError::Config("API URL not configured — needed for nonce auto-management".to_string())
        })?;

        let url = format!("{}/account/{}/nonce", api_url.trim_end_matches('/'), did);
        let resp = self.http_client.get(&url).send().await
            .map_err(|e| WillowError::Network(format!("Failed to fetch nonce: {}", e)))?;
        let body: serde_json::Value = resp.json().await
            .map_err(|e| WillowError::Network(format!("Failed to parse nonce response: {}", e)))?;

        // Response format: {"success": true, "data": {"did": "...", "nonce": N}}
        let base_nonce = body
            .get("data")
            .and_then(|d| d.get("nonce"))
            .and_then(|n| n.as_u64())
            .unwrap_or(0);

        Ok(base_nonce + 1)
    }

    /// Register a DID through consensus
    pub async fn register_did(
        &self,
        did_document: &DidDocument,
        private_key_hex: &str,
        public_key_id: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<String> {
        let nonce = self.get_next_nonce(&did_document.id).await?;
        let did_doc_json = serde_json::to_string(did_document)?;
        let signature_hex = sign_challenge(&did_doc_json, private_key_hex, algorithm)?;
        let signature_bytes = hex::decode(signature_hex)?;

        // Create transaction
        let register_tx = RegisterDidTx {
            did_document: did_document.clone(),
            signature: signature_bytes,
            public_key_id: public_key_id.to_string(),
            nonce,
        };

        let tx_json = Self::serialize_tx("RegisterDid", &register_tx)?;
        self.submit_transaction(&tx_json).await
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
        let nonce = self.get_next_nonce(from_did).await?;
        let transfer_message = format!(
            "Transfer\nFrom: {}\nTo: {}\nAmount: {}\nMemo: {}\nNonce: {}",
            from_did,
            to_did,
            amount,
            memo.as_ref().unwrap_or(&"".to_string()),
            nonce
        );

        // Sign the message
        let signature_hex = sign_challenge(&transfer_message, private_key_hex, algorithm)?;
        let signature_bytes = hex::decode(signature_hex)?;

        // Create transaction
        let transfer_tx = TransferTx {
            from_did: from_did.to_string(),
            to_did: to_did.to_string(),
            amount,
            memo,
            signature: signature_bytes,
            public_key_id: public_key_id.to_string(),
            nonce,
        };

        let tx_json = Self::serialize_tx("Transfer", &transfer_tx)?;
        self.submit_transaction(&tx_json).await
    }

    /// Submit a raw JSON transaction to CometBFT.
    ///
    /// This is a public wrapper around submit_transaction for CLI/external use.
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

    /// Submit a transaction to CometBFT
    /// Submit a pre-serialized transaction JSON string to CometBFT.
    pub async fn submit_transaction_json(&self, tx_json: &str) -> Result<String> {
        self.submit_transaction(tx_json).await
    }

    async fn submit_transaction(&self, tx_json: &str) -> Result<String> {
        // Base64 encode the serialized transaction
        let tx_base64 = base64::engine::general_purpose::STANDARD.encode(tx_json.as_bytes());

        // Create JSON-RPC request
        let rpc_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "broadcast_tx_sync",
            "params": {
                "tx": tx_base64
            }
        });

        // Submit to CometBFT
        let response = self
            .http_client
            .post(&self.consensus_rpc_url)
            .json(&rpc_request)
            .send()
            .await?;

        let response_text = response.text().await?;
        let rpc_response: CometBftResponse =
            serde_json::from_str(&response_text).map_err(|e| WillowError::Serialization(e))?;

        // Check for errors
        if let Some(error) = rpc_response.error {
            return Err(WillowError::Custom(format!(
                "CometBFT error: {} ({}){}",
                error.message,
                error.code,
                error
                    .data
                    .as_ref()
                    .map(|d| format!(": {}", d))
                    .unwrap_or_default()
            )));
        }

        // Check result
        if let Some(result) = rpc_response.result {
            if result.code != 0 {
                return Err(WillowError::Custom(format!(
                    "Transaction failed: {} (code: {})",
                    result.log, result.code
                )));
            }
            Ok(result.hash)
        } else {
            Err(WillowError::Custom("No result in response".to_string()))
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

    /// Register a subgrove using SigningKey
    pub async fn register_subgrove(
        &self,
        mut request: RegisterSubgroveRequest,
        signing_key: &SigningKey,
    ) -> Result<String> {
        use sha3::{Digest, Keccak256};

        request.nonce = self.get_next_nonce(&request.owner_did).await?;

        let schema_json = request
            .schema
            .as_ref()
            .map(|s| serde_json::to_string(s).unwrap())
            .unwrap_or_else(|| "{}".to_string());

        // Hash the schema for more efficient signatures
        let mut hasher = Keccak256::new();
        hasher.update(schema_json.as_bytes());
        let schema_hash = hasher.finalize();
        let schema_hash_hex = hex::encode(schema_hash);

        // Build canonical sign message based on mode
        let message = format!(
            "RegisterSubgrove\nID: {}\nName: {}\nDescription: {}\nSchemaHash: {}\nOwner: {}\nAdmins: {}\nWriters: {}\nReaders: {}\nNonce: {}",
            request.subgrove_id,
            request.name,
            request.description,
            schema_hash_hex,
            request.owner_did,
            request.admins.join(","),
            request.writers.join(","),
            request.readers.join(","),
            request.nonce
        );

        // Sign with Ed25519 key
        let signature = signing_key.sign(message.as_bytes());
        request.signature = signature.to_bytes().to_vec();

        // Create transaction with DataStorage mode (SDK default)
        let register_tx = RegisterSubgroveTx {
            subgrove_id: request.subgrove_id.clone(),
            name: request.name.clone(),
            description: request.description.clone(),
            schema: schema_json,
            owner_did: request.owner_did.clone(),
            admins: request.admins.clone(),
            initial_funding: request.initial_funding,
            mode: SubgroveMode::DataStorage {
                name: request.name.clone(),
                writers: request.writers.clone(),
                free_readers: request.readers.clone(),
                read_pricing: None,
            },
            checkpoint_verification: Default::default(),
            privacy: None,
            initial_owner_key_grant: None,
            signature: request.signature.clone(),
            public_key_id: request.public_key_id.clone(),
            nonce: request.nonce,
        };
        let tx_json = Self::serialize_tx("RegisterSubgrove", &register_tx)?;
        self.submit_transaction(&tx_json).await
    }

    /// Register a file storage subgrove using SigningKey.
    ///
    /// File storage subgroves store files with chunk-level Merkle verification
    /// via dedicated storage nodes.
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
    ) -> Result<String> {
        let nonce = self.get_next_nonce(owner_did).await?;
        use sha3::{Digest, Keccak256};

        let schema_json = "{}";
        let mut hasher = Keccak256::new();
        hasher.update(schema_json.as_bytes());
        let schema_hash_hex = hex::encode(hasher.finalize());

        let message = format!(
            "RegisterSubgrove\nID: {}\nMode: FileStorage\nName: {}\nDescription: \nSchemaHash: {}\nOwner: {}\nAdmins: \nWriters: {}\nReaders: {}\nNonce: {}",
            subgrove_id, name, schema_hash_hex, owner_did,
            writers.join(","), readers.join(","), nonce
        );

        let signature = signing_key.sign(message.as_bytes());

        let register_tx = RegisterSubgroveTx {
            subgrove_id: subgrove_id.to_string(),
            name: name.to_string(),
            description: String::new(),
            schema: schema_json.to_string(),
            owner_did: owner_did.to_string(),
            admins: vec![],
            initial_funding: None,
            mode: SubgroveMode::FileStorage {
                name: name.to_string(),
                max_file_size,
                replication_factor,
                writers,
                free_readers: readers,
                read_pricing: None,
                retention_period: 0,
            },
            checkpoint_verification: Default::default(),
            privacy: None,
            initial_owner_key_grant: None,
            signature: signature.to_bytes().to_vec(),
            public_key_id: public_key_id.to_string(),
            nonce,
        };
        let tx_json = Self::serialize_tx("RegisterSubgrove", &register_tx)?;
        self.submit_transaction(&tx_json).await
    }

    /// Register a blockchain indexing subgrove from a definition file.
    ///
    /// Loads the subgrove definition, signs it, and submits the transaction.
    /// This is the simplest way to deploy a predefined subgrove.
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
    ) -> Result<String> {
        let nonce = self.get_next_nonce(owner_did).await?;
        let payload = definition.signing_payload(owner_did, nonce);
        let signature = signing_key.sign(payload.as_bytes());

        let tx_json = definition.to_register_transaction(
            owner_did,
            public_key_id,
            signature.to_bytes().to_vec(),
            nonce,
        );

        self.submit_transaction(&tx_json).await
    }

    /// Store data using SigningKey
    pub async fn store_data(
        &self,
        mut request: StoreDataRequest,
        signing_key: &SigningKey,
    ) -> Result<String> {
        request.nonce = self.get_next_nonce(&request.owner_did).await?;
        let data_json =
            serde_json::to_string(&request.data).map_err(|e| WillowError::Serialization(e))?;
        let message = format!(
            "{}:{}:{}",
            request.subgrove_id, request.key, data_json
        );

        // Sign the message
        let signature = signing_key.sign(message.as_bytes());
        request.signature = signature.to_bytes().to_vec();

        let tx_json = Self::serialize_tx("StoreData", &request)?;
        self.submit_transaction(&tx_json).await
    }

    /// Delete data using SigningKey
    pub async fn delete_data(
        &self,
        subgrove_id: &str,
        key: &str,
        owner_did: &str,
        public_key_id: &str,
        signing_key: &SigningKey,
    ) -> Result<String> {
        let nonce = self.get_next_nonce(owner_did).await?;
        let message = format!("DeleteData:{}:{}", subgrove_id, key);
        let signature = signing_key.sign(message.as_bytes());

        let delete_tx = DeleteDataTx {
            subgrove_id: subgrove_id.to_string(),
            key: key.to_string(),
            owner_did: owner_did.to_string(),
            signature: signature.to_bytes().to_vec(),
            public_key_id: public_key_id.to_string(),
            nonce,
        };
        let tx_json = Self::serialize_tx("DeleteData", &delete_tx)?;
        self.submit_transaction(&tx_json).await
    }

    /// Fund a subgrove using SigningKey
    pub async fn fund_subgrove(
        &self,
        mut request: crate::types::FundSubgroveRequest,
        signing_key: &SigningKey,
    ) -> Result<String> {
        request.nonce = self.get_next_nonce(&request.from_did).await?;
        let signing_payload = format!(
            "FundSubgrove\nSubgrove: {}\nAmount: {}\nFrom: {}\nNonce: {}",
            request.subgrove_id, request.amount, request.from_did, request.nonce
        );

        // Sign with Ed25519 key
        let signature = signing_key.sign(signing_payload.as_bytes());

        let fund_tx = FundSubgroveTx {
            subgrove_id: request.subgrove_id,
            amount: request.amount,
            from_did: request.from_did,
            signature: signature.to_bytes().to_vec(),
            public_key_id: request.public_key_id,
            nonce: request.nonce,
        };
        let tx_json = Self::serialize_tx("FundSubgrove", &fund_tx)?;
        self.submit_transaction(&tx_json).await
    }

    /// Deregister (delete) a subgrove using SigningKey.
    ///
    /// Remaining subgrove funding balance is refunded to the owner.
    pub async fn deregister_subgrove(
        &self,
        mut request: crate::types::DeregisterSubgroveRequest,
        signing_key: &SigningKey,
    ) -> Result<String> {
        request.nonce = self.get_next_nonce(&request.owner_did).await?;
        let signing_payload = format!(
            "DeregisterSubgrove:{}:{}:{}",
            request.subgrove_id, request.owner_did, request.nonce
        );

        let signature = signing_key.sign(signing_payload.as_bytes());

        let deregister_tx = DeregisterSubgroveTx {
            subgrove_id: request.subgrove_id,
            owner_did: request.owner_did,
            signature: signature.to_bytes().to_vec(),
            public_key_id: request.public_key_id,
            nonce: request.nonce,
        };
        let tx_json = Self::serialize_tx("DeregisterSubgrove", &deregister_tx)?;
        self.submit_transaction(&tx_json).await
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
            signature: vec![7, 8, 9],
            public_key_id: "did:willow:owner#key-1".to_string(),
            nonce: 3,
        };

        let json = serde_json::to_string(&tx).unwrap();
        let deserialized: RegisterSubgroveTx = serde_json::from_str(&json).unwrap();

        assert_eq!(tx.subgrove_id, deserialized.subgrove_id);
        assert_eq!(tx.schema, deserialized.schema);
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
}
