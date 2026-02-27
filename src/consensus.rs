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

/// Register App transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAppTx {
    pub app_id: String,
    pub name: String,
    pub description: String,
    pub app_type: String,
    pub owner_did: String,
    pub admins: Vec<String>,
    #[serde(default)]
    pub initial_funding: Option<u128>,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub nonce: u64,
}

/// The mode of a subgrove: either data storage or blockchain indexing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SubgroveMode {
    /// Data storage mode — stores arbitrary off-chain data with verification.
    DataStorage {
        name: String,
        #[serde(default)]
        writers: Vec<String>,
        #[serde(default)]
        readers: Vec<String>,
        #[serde(default)]
        read_pricing: Option<serde_json::Value>,
        #[serde(default = "default_required_verifications")]
        required_verifications: u32,
    },
    /// Blockchain indexing mode — indexes on-chain data with WASM transformations.
    BlockchainIndexing {
        manifest_ipfs: String,
        #[serde(default)]
        manifest_content: Vec<u8>,
        #[serde(default)]
        wasm_modules: Vec<serde_json::Value>,
        #[serde(default)]
        execution_mode: serde_json::Value,
        #[serde(default)]
        indexer_config: serde_json::Value,
    },
}

fn default_required_verifications() -> u32 {
    3
}

impl Default for SubgroveMode {
    fn default() -> Self {
        SubgroveMode::DataStorage {
            name: String::new(),
            writers: Vec::new(),
            readers: Vec::new(),
            read_pricing: None,
            required_verifications: 3,
        }
    }
}

/// Register Subgrove transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSubgroveTx {
    pub subgrove_id: String,
    pub app_id: String,
    pub schema: String, // JSON schema
    pub owner_did: String,
    #[serde(default)]
    pub mode: SubgroveMode,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub nonce: u64,
}

/// Transfer transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferTx {
    pub from_did: String,
    pub to_did: String,
    pub amount: u128,
    pub memo: Option<String>,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub nonce: u64,
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

/// Consensus client for submitting transactions
pub struct ConsensusClient {
    http_client: Client,
    consensus_rpc_url: String,
}

impl ConsensusClient {
    /// Create a new consensus client
    pub fn new(consensus_rpc_url: &str) -> Self {
        Self {
            http_client: Client::new(),
            consensus_rpc_url: consensus_rpc_url.to_string(),
        }
    }

    /// Register a DID through consensus
    pub async fn register_did(
        &self,
        did_document: &DidDocument,
        private_key_hex: &str,
        public_key_id: &str,
        algorithm: SignatureAlgorithm,
        nonce: u64,
    ) -> Result<String> {
        // Sign the DID document
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

        // Create transaction in the exact format that works
        let transaction = json!({
            "RegisterDid": register_tx
        });

        // Submit transaction
        self.submit_transaction(&transaction).await
    }

    /// Register an app through consensus
    pub async fn register_app(
        &self,
        app_id: &str,
        name: &str,
        description: &str,
        app_type: &str,
        owner_did: &str,
        admins: Vec<String>,
        private_key_hex: &str,
        public_key_id: &str,
        algorithm: SignatureAlgorithm,
        nonce: u64,
        initial_funding: Option<u128>,
    ) -> Result<String> {
        // Create app registration message to sign
        let mut app_message = format!(
            "RegisterApp\nID: {}\nName: {}\nDescription: {}\nType: {}\nOwner: {}\nAdmins: {}\nNonce: {}",
            app_id, name, description, app_type, owner_did, admins.join(","), nonce
        );
        if let Some(amount) = initial_funding {
            if amount > 0 {
                app_message.push_str(&format!("\nFunding: {}", amount));
            }
        }

        // Sign the message
        let signature_hex = sign_challenge(&app_message, private_key_hex, algorithm)?;
        let signature_bytes = hex::decode(signature_hex)?;

        // Create transaction
        let register_tx = RegisterAppTx {
            app_id: app_id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            app_type: app_type.to_string(),
            owner_did: owner_did.to_string(),
            admins,
            initial_funding,
            signature: signature_bytes,
            public_key_id: public_key_id.to_string(),
            nonce,
        };

        let transaction = json!({
            "RegisterApp": register_tx
        });

        self.submit_transaction(&transaction).await
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
        nonce: u64,
    ) -> Result<String> {
        // Create transfer message to sign
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

        let transaction = json!({
            "Transfer": transfer_tx
        });

        self.submit_transaction(&transaction).await
    }

    /// Submit a raw JSON transaction to CometBFT.
    ///
    /// This is a public wrapper around submit_transaction for CLI/external use.
    pub async fn submit_raw_transaction(&self, transaction: serde_json::Value) -> Result<String> {
        self.submit_transaction(&transaction).await
    }

    /// Submit a transaction to CometBFT
    async fn submit_transaction(&self, transaction: &serde_json::Value) -> Result<String> {
        // Serialize transaction and base64 encode
        let tx_json = serde_json::to_string(transaction)?;
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

    /// Wait for transaction to be included in a block
    pub async fn wait_for_transaction(&self, tx_hash: &str, max_attempts: u32) -> Result<bool> {
        for _ in 0..max_attempts {
            // Query transaction status
            let query_request = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tx",
                "params": {
                    "hash": tx_hash,
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

        // Create message to sign
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
            "RegisterSubgrove\nID: {}\nApp: {}\nName: {}\nSchemaHash: {}\nOwner: {}\nWriters: {}\nReaders: {}\nNonce: {}",
            request.subgrove_id,
            request.app_id,
            request.name,
            schema_hash_hex,
            request.owner_did,
            request.writers.join(","),
            request.readers.join(","),
            request.nonce
        );

        // Sign with Ed25519 key
        let signature = signing_key.sign(message.as_bytes());
        request.signature = signature.to_bytes().to_vec();

        // Create transaction with DataStorage mode (SDK default)
        let transaction = json!({
            "RegisterSubgrove": {
                "subgrove_id": request.subgrove_id,
                "app_id": request.app_id,
                "schema": schema_json,
                "owner_did": request.owner_did,
                "mode": {
                    "DataStorage": {
                        "name": request.name,
                        "writers": request.writers,
                        "free_readers": request.readers,
                        "read_pricing": null,
                        "required_verifications": 3
                    }
                },
                "signature": request.signature,
                "public_key_id": request.public_key_id,
                "nonce": request.nonce,
            }
        });

        self.submit_transaction(&transaction).await
    }

    /// Store data using SigningKey
    pub async fn store_data(
        &self,
        mut request: StoreDataRequest,
        signing_key: &SigningKey,
    ) -> Result<String> {
        // Create the message to sign in the format expected by consensus
        let data_json =
            serde_json::to_string(&request.data).map_err(|e| WillowError::Serialization(e))?;
        let message = format!(
            "{}:{}:{}:{}",
            request.app_id, request.subgrove_id, request.key, data_json
        );

        // Sign the message
        let signature = signing_key.sign(message.as_bytes());
        request.signature = signature.to_bytes().to_vec();

        // Create transaction
        let transaction = json!({
            "StoreData": request
        });

        self.submit_transaction(&transaction).await
    }

    /// Fund an app using SigningKey
    pub async fn fund_app(
        &self,
        request: crate::types::FundAppRequest,
        signing_key: &SigningKey,
    ) -> Result<String> {
        // Construct canonical signing payload
        let signing_payload = format!(
            "FundApp:{}:{}:{}:{}",
            request.app_id, request.amount, request.from_did, request.nonce
        );

        // Sign with Ed25519 key
        let signature = signing_key.sign(signing_payload.as_bytes());

        // Create transaction matching server structure
        let transaction = json!({
            "FundApp": {
                "app_id": request.app_id,
                "amount": request.amount,
                "from_did": request.from_did,
                "signature": signature.to_bytes().to_vec(),
                "public_key_id": request.public_key_id,
                "nonce": request.nonce,
            }
        });

        self.submit_transaction(&transaction).await
    }

    /// Get transaction result
    pub async fn get_transaction(&self, tx_hash: &str) -> Result<TransactionResult> {
        let query_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tx",
            "params": {
                "hash": format!("0x{}", tx_hash),
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
    fn test_register_app_tx_serialization() {
        let tx = RegisterAppTx {
            app_id: "test-app".to_string(),
            name: "Test App".to_string(),
            description: "A test application".to_string(),
            app_type: "indexing".to_string(),
            owner_did: "did:willow:owner".to_string(),
            admins: vec!["did:willow:admin".to_string()],
            initial_funding: None,
            signature: vec![4, 5, 6],
            public_key_id: "did:willow:owner#key-1".to_string(),
            nonce: 2,
        };

        let json = serde_json::to_string(&tx).unwrap();
        let deserialized: RegisterAppTx = serde_json::from_str(&json).unwrap();

        assert_eq!(tx.app_id, deserialized.app_id);
        assert_eq!(tx.name, deserialized.name);
        assert_eq!(tx.admins, deserialized.admins);
    }

    #[test]
    fn test_register_subgrove_tx_serialization() {
        let tx = RegisterSubgroveTx {
            subgrove_id: "test-subgrove".to_string(),
            app_id: "test-app".to_string(),
            schema: r#"{"type":"object"}"#.to_string(),
            owner_did: "did:willow:owner".to_string(),
            mode: SubgroveMode::DataStorage {
                name: "Test Subgrove".to_string(),
                writers: vec!["did:willow:writer".to_string()],
                readers: vec!["did:willow:reader".to_string()],
                read_pricing: None,
                required_verifications: 3,
            },
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
