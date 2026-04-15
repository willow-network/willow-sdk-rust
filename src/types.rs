//! Type definitions for Willow SDK.
//!
//! This module contains all data structures used for communicating with
//! the Willow API, including request/response types, DID documents, and
//! indexing-related structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Signature algorithm for DIDs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

impl SignatureAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Ed25519 => "Ed25519",
            SignatureAlgorithm::Secp256k1 => "secp256k1",
        }
    }
}

pub use willow_types::consensus::transactions::{
    DidDocument, PublicKey, ServiceEndpoint,
};

/// DID information including keys
#[derive(Debug, Clone)]
pub struct DidInfo {
    pub did: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub public_key_id: String,
    pub did_document: DidDocument,
    pub algorithm: SignatureAlgorithm,
}

impl DidInfo {
    pub fn private_key_hex(&self) -> String {
        hex::encode(&self.private_key)
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }
}

/// Per-request signature headers for authentication.
/// Message format: {METHOD}:{PATH}:{TIMESTAMP}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRequestHeaders {
    /// The DID being authenticated
    #[serde(rename = "X-DID")]
    pub x_did: String,
    /// Which key in the DID doc signed this
    #[serde(rename = "X-Public-Key-ID")]
    pub x_public_key_id: String,
    /// Hex-encoded signature over the message
    #[serde(rename = "X-Signature")]
    pub x_signature: String,
    /// Unix timestamp (must be within 300s of server time)
    #[serde(rename = "X-Timestamp")]
    pub x_timestamp: String,
}

/// Supported field types for schema definitions
pub use willow_types::storage::types::FieldType;

/// Schema field definition (convenience wrapper used in some APIs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaField {
    #[serde(rename = "type")]
    pub field_type: String,
    pub required: bool,
    #[serde(default)]
    pub indexed: bool,
}

pub use willow_types::storage::types::{IndexDefinition, SchemaDefinition};

/// Subgrove registration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSubgroveRequest {
    pub subgrove_id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaDefinition>,
    pub owner_did: String,
    #[serde(default)]
    pub admins: Vec<String>,
    #[serde(default)]
    pub initial_funding: Option<u128>,
    #[serde(default)]
    pub writers: Vec<String>,
    #[serde(default)]
    pub readers: Vec<String>,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub nonce: u64,
}

pub use willow_types::storage::types::SubgroveRegistration;

/// Generic API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

/// Proof data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofData {
    pub proof: String,
    pub value: Option<serde_json::Value>,
}

/// Permission role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionRole {
    Owner,
    Admin,
    Writer,
    Reader,
}

/// Store data request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreDataRequest {
    pub subgrove_id: String,
    pub key: String,
    pub data: serde_json::Value,
    pub owner_did: String,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub nonce: u64,
}

/// Fund subgrove request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundSubgroveRequest {
    pub subgrove_id: String,
    pub amount: u128,
    pub from_did: String,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub nonce: u64,
}

/// Deregister subgrove request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeregisterSubgroveRequest {
    pub subgrove_id: String,
    pub owner_did: String,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub nonce: u64,
}

// ============================================================================
// Token Types
// ============================================================================

/// Token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token name (e.g., "Willow")
    pub name: String,
    /// Token symbol (e.g., "WILL")
    pub symbol: String,
    /// Number of decimal places
    pub decimals: u8,
    /// Genesis allocation (pre-mined supply)
    pub genesis_supply: u128,
    /// Tokens minted via block rewards
    pub minted_supply: u128,
    /// Hard cap on total supply
    pub max_supply: u128,
    /// Current circulating supply (genesis + minted)
    pub circulating_supply: u128,
}

/// Balance information for a DID or app
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceInfo {
    /// Account DID
    pub did: String,
    /// Available (spendable) balance
    pub available: u128,
    /// Staked balance (for validators)
    #[serde(default)]
    pub staked: u128,
    /// Locked balance (unbonding)
    #[serde(default)]
    pub locked: u128,
}

/// Balance information for a subgrove
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveBalanceInfo {
    /// Subgrove ID
    pub subgrove_id: String,
    /// Available balance
    pub balance: u128,
    /// Total amount spent
    #[serde(default)]
    pub total_spent: u128,
    /// Last funded timestamp
    #[serde(default)]
    pub last_funded: u64,
}

/// Token transfer request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub from_did: String,
    pub to_did: String,
    pub amount: u128,
    pub memo: Option<String>,
}

// ============================================================================
// Fee Types
// ============================================================================

pub use willow_types::FeeSchedule;

// ============================================================================
// Validator Types
// ============================================================================

/// Validator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator DID
    pub did: String,
    /// Total staked amount (self + delegated)
    pub total_stake: u128,
    /// Self-staked amount
    pub self_stake: u128,
    /// Whether the validator is active
    pub active: bool,
    /// Whether the validator is jailed
    pub jailed: bool,
    /// Jail end time (Unix timestamp), if jailed
    #[serde(default)]
    pub jail_end_time: Option<u64>,
    /// Consensus public key (hex)
    #[serde(default)]
    pub consensus_pubkey: Option<String>,
}

/// Stake request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeRequest {
    pub validator_did: String,
    pub amount: u128,
    pub consensus_pubkey: String,
}

/// Unstake request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnstakeRequest {
    pub validator_did: String,
    pub amount: u128,
}

// ============================================================================
// GraphQL / Indexing Types
// ============================================================================

/// GraphQL query request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLRequest {
    /// The GraphQL query string
    pub query: String,
    /// Optional variables for the query
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<serde_json::Value>,
}

/// GraphQL query response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLResponse {
    /// Query result data
    pub data: Option<serde_json::Value>,
    /// Errors if any occurred
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<GraphQLError>>,
    /// Cryptographic proof of the result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<QueryProof>,
}

/// Request body for SQL queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_proof: Option<bool>,
}

/// Response from a SQL query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlResponse {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<QueryProof>,
}

/// GraphQL error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
}

/// Cryptographic proof for query results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryProof {
    /// Individual merkle proofs for each data item
    pub merkle_proofs: Vec<MerkleProof>,
    /// State root hash
    pub state_root: Vec<u8>,
    /// Block height at which the query was executed
    pub block_height: u64,
    /// Optional Ethereum anchor information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ethereum_anchor: Option<EthereumAnchor>,
}

/// Merkle proof for a single data item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Key being proven
    pub key: String,
    /// Hash of the value
    pub value_hash: Vec<u8>,
    /// Sibling hashes for proof verification
    pub siblings: Vec<Vec<u8>>,
    /// Path in the tree
    pub path: String,
}

/// Ethereum anchor for cross-chain verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumAnchor {
    /// Ethereum block number containing the anchor
    pub block_number: u64,
    /// Transaction hash
    pub tx_hash: Vec<u8>,
    /// Contract address
    pub contract: String,
}

// ============================================================================
// Subgrove / Indexer Types
// ============================================================================

/// Subgrove information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveInfo {
    /// Unique subgrove identifier
    pub subgrove_id: String,
    /// Human-readable name
    pub name: String,
    /// Owner DID
    pub owner_did: String,
    /// Current status
    pub status: SubgroveStatus,
    /// Latest indexed block
    pub latest_block: u64,
    /// Indexers currently serving this subgrove
    pub indexers: Vec<String>,
}

/// Subgrove status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubgroveStatus {
    /// Currently being indexed
    Syncing,
    /// Fully synced and serving queries
    Synced,
    /// Paused
    Paused,
    /// Failed to index
    Failed,
}

/// Subgrove indexing status with detailed progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveIndexingStatus {
    /// Subgrove identifier
    pub subgrove_id: String,
    /// Current synced block
    pub synced_block: u64,
    /// Target block (chain head)
    pub target_block: u64,
    /// Sync progress percentage (0.0 - 100.0)
    pub progress_percentage: f64,
    /// Status message
    pub status: String,
    /// Last error if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Indexer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerInfo {
    /// Indexer's DID
    pub indexer_did: String,
    /// Subgroves being indexed
    pub subgroves: Vec<String>,
    /// Total staked amount
    pub stake_amount: u128,
    /// Monitoring / health endpoint (historically also used for queries).
    pub endpoint: String,
    /// Optional dedicated endpoint for client query traffic
    /// (GraphQL/SQL/historical). When absent, callers fall back to `endpoint`.
    /// See [`IndexerInfo::effective_query_endpoint`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_endpoint: Option<String>,
    /// Current status
    pub status: IndexerStatus,
    /// Performance score (0.0 - 100.0)
    pub performance_score: f64,
    /// Last update timestamp
    pub last_update: u64,
}

impl IndexerInfo {
    /// URL clients should POST GraphQL/SQL queries to. Prefers
    /// `query_endpoint` when set; falls back to `endpoint` otherwise.
    pub fn effective_query_endpoint(&self) -> &str {
        self.query_endpoint.as_deref().unwrap_or(&self.endpoint)
    }
}

/// Indexer status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexerStatus {
    /// Active and serving queries
    Active,
    /// Registered but not active
    Inactive,
    /// Slashed for misbehavior
    Slashed,
}

impl Default for IndexerStatus {
    fn default() -> Self {
        Self::Inactive
    }
}

// ============================================================================
// Verification Types
// ============================================================================

/// Verification statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStats {
    /// Total blocks processed
    pub total_blocks: u64,
    /// Blocks successfully verified
    pub verified_blocks: u64,
    /// Blocks pending verification
    pub unverified_blocks: u64,
    /// Blocks that reached finality
    pub finalized_blocks: u64,
    /// Blocks that failed verification
    pub failed_blocks: u64,
    /// Verification success rate (0.0 - 1.0)
    pub verification_rate: f64,
}

/// Block verification status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockVerificationStatus {
    /// Block number
    pub block_number: u64,
    /// Verification status string
    pub status: String,
    /// Timestamp when verified (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<u64>,
    /// Timestamp when finalized (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalized_at: Option<u64>,
    /// Confidence level (0.0 - 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

/// Verify proof request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyProofRequest {
    /// Hex-encoded proof bytes
    pub proof: String,
    /// Documents to verify
    pub documents: Vec<serde_json::Value>,
    /// Optional path query information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_query: Option<PathQueryData>,
}

/// Path query data for proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathQueryData {
    /// Path components
    pub path: Vec<String>,
    /// Query specification
    pub query: serde_json::Value,
}

/// Verify proof response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyProofResponse {
    /// Whether the proof is valid
    pub valid: bool,
    /// Computed root hash (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_hash: Option<String>,
    /// Error message if verification failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// Identity Extensions
// ============================================================================

/// DID permissions response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidPermissions {
    /// DID this refers to
    pub did: String,
    /// Subgroves where this DID is owner
    pub owned_subgroves: Vec<String>,
    /// Subgroves where this DID is admin
    pub admin_subgroves: Vec<String>,
    /// Subgroves where this DID has write access
    pub write_access: Vec<String>,
    /// Subgroves where this DID has read access
    pub read_access: Vec<String>,
}

// ============================================================================
// Health / Status Types
// ============================================================================

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall health status
    pub status: String,
    /// Current timestamp (RFC3339 string)
    pub timestamp: String,
    /// Version information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Individual component health checks
    #[serde(default, alias = "components")]
    pub checks: HashMap<String, ComponentHealth>,
}

/// Individual component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component status (absent for info-only checks like "system")
    #[serde(default)]
    pub status: Option<String>,
    /// Optional message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Additional fields (e.g. uptime_seconds for system check)
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // SignatureAlgorithm Tests
    // ========================================================================

    #[test]
    fn test_signature_algorithm_as_str() {
        assert_eq!(SignatureAlgorithm::Ed25519.as_str(), "Ed25519");
        assert_eq!(SignatureAlgorithm::Secp256k1.as_str(), "secp256k1");
    }

    #[test]
    fn test_signature_algorithm_serialization() {
        let ed25519 = SignatureAlgorithm::Ed25519;
        let json = serde_json::to_string(&ed25519).unwrap();
        assert_eq!(json, "\"Ed25519\"");

        let secp = SignatureAlgorithm::Secp256k1;
        let json = serde_json::to_string(&secp).unwrap();
        assert_eq!(json, "\"secp256k1\"");
    }

    #[test]
    fn test_signature_algorithm_deserialization() {
        let ed25519: SignatureAlgorithm = serde_json::from_str("\"Ed25519\"").unwrap();
        assert_eq!(ed25519, SignatureAlgorithm::Ed25519);

        let secp: SignatureAlgorithm = serde_json::from_str("\"secp256k1\"").unwrap();
        assert_eq!(secp, SignatureAlgorithm::Secp256k1);
    }

    // ========================================================================
    // DidDocument Tests
    // ========================================================================

    #[test]
    fn test_did_document_serialization() {
        let doc = DidDocument {
            id: "did:willow:test123".to_string(),
            public_keys: vec![PublicKey {
                id: "did:willow:test123#key-1".to_string(),
                key_type: "Ed25519VerificationKey2020".to_string(),
                controller: "did:willow:test123".to_string(),
                public_key_hex: Some("abcd1234".to_string()),
                public_key_base58: None,
            }],
            authentication: vec!["did:willow:test123#key-1".to_string()],
            service: vec![],
            created: 1234567890,
            updated: 1234567890,
            proof: None,
        };

        let json = serde_json::to_string(&doc).unwrap();
        let deserialized: DidDocument = serde_json::from_str(&json).unwrap();

        assert_eq!(doc.id, deserialized.id);
        assert_eq!(doc.public_keys.len(), deserialized.public_keys.len());
        assert_eq!(doc.authentication, deserialized.authentication);
    }

    #[test]
    fn test_did_document_with_service() {
        let doc = DidDocument {
            id: "did:willow:test".to_string(),
            public_keys: vec![],
            authentication: vec![],
            service: vec![ServiceEndpoint {
                id: "did:willow:test#api".to_string(),
                service_type: "WillowAPI".to_string(),
                service_endpoint: "https://api.example.com".to_string(),
            }],
            created: 1000,
            updated: 2000,
            proof: None,
        };

        let json = serde_json::to_string(&doc).unwrap();
        let deserialized: DidDocument = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.service.len(), 1);
        assert_eq!(
            deserialized.service[0].service_endpoint,
            "https://api.example.com"
        );
    }

    // ========================================================================
    // DidInfo Tests
    // ========================================================================

    #[test]
    fn test_did_info_hex_encoding() {
        let info = DidInfo {
            did: "did:willow:test".to_string(),
            private_key: vec![0xde, 0xad, 0xbe, 0xef],
            public_key: vec![0xca, 0xfe, 0xba, 0xbe],
            public_key_id: "did:willow:test#key-1".to_string(),
            did_document: DidDocument {
                id: "did:willow:test".to_string(),
                public_keys: vec![],
                authentication: vec![],
                service: vec![],
                created: 0,
                updated: 0,
                proof: None,
            },
            algorithm: SignatureAlgorithm::Ed25519,
        };

        assert_eq!(info.private_key_hex(), "deadbeef");
        assert_eq!(info.public_key_hex(), "cafebabe");
    }

    // ========================================================================
    // Schema Types Tests
    // ========================================================================

    #[test]
    fn test_schema_field_serialization() {
        let field = SchemaField {
            field_type: "string".to_string(),
            required: true,
            indexed: true,
        };

        let json = serde_json::to_string(&field).unwrap();
        let deserialized: SchemaField = serde_json::from_str(&json).unwrap();

        assert_eq!(field.field_type, deserialized.field_type);
        assert_eq!(field.required, deserialized.required);
        assert_eq!(field.indexed, deserialized.indexed);
    }

    // ========================================================================
    // Health Status Tests
    // ========================================================================

    #[test]
    fn test_health_status_serialization() {
        let mut components = HashMap::new();
        components.insert(
            "database".to_string(),
            ComponentHealth {
                status: Some("healthy".to_string()),
                message: None,
                extra: HashMap::new(),
            },
        );
        components.insert(
            "consensus".to_string(),
            ComponentHealth {
                status: Some("healthy".to_string()),
                message: Some("Synced to height 100".to_string()),
                extra: HashMap::new(),
            },
        );

        let health = HealthStatus {
            status: "healthy".to_string(),
            timestamp: "2026-03-31T16:20:07Z".to_string(),
            version: Some("1.0.0".to_string()),
            checks: components,
        };

        let json = serde_json::to_string(&health).unwrap();
        let deserialized: HealthStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(health.status, deserialized.status);
        assert_eq!(health.checks.len(), deserialized.checks.len());
    }
}
