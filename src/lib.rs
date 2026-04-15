//! # Willow Rust SDK
//!
//! A Rust SDK for interacting with the Willow decentralized data indexing protocol.
//!
//! ## Features
//!
//! - **Trustless verification by default**: Embedded light client verifies all data
//! - **DID management**: Ed25519 and secp256k1 support for decentralized identity
//! - **Authenticated data operations**: CRUD with cryptographic signatures
//! - **Merkle proof verification**: All data verified against blockchain consensus
//! - **Type-safe API**: Strong error handling with Result types
//! - **Async/await support**: Built for Tokio runtime
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use willow_sdk::{WillowClient, DEVNET_VALIDATOR_1};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create client with API and consensus endpoints
//!     let client = WillowClient::builder()
//!         .api_url("http://localhost:3031")
//!         .consensus_url("http://localhost:26657") // Optional: for consensus operations
//!         .build()
//!         .await?;
//!
//!     // Set identity for per-request signing (or your own DID)
//!     client.set_identity(
//!         DEVNET_VALIDATOR_1.did,
//!         DEVNET_VALIDATOR_1.private_key,
//!         DEVNET_VALIDATOR_1.public_key_id
//!     );
//!
//!     // All data operations are automatically verified against consensus
//!     let data = client.data().get("dataset", "key").await?;
//!
//!     // Consensus operations (DID registration, transfers, etc.)
//!     // client.consensus().register_did(...).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Light Client Verification
//!
//! The SDK includes an embedded light client that provides trustless verification
//! by default. This uses GroveDB's lightweight verify-only mode (no RocksDB).
//!
//! - **Trustless**: Verifies proofs against CometBFT consensus
//! - **Lightweight**: Only ~5 additional dependencies
//! - **Automatic**: All data operations verified by default
//!
//! To disable verification (if you trust your node):
//! ```toml
//! [dependencies]
//! willow-sdk = { version = "0.1", features = ["no-light-client"] }
//! ```
//!
//! For performance-critical scenarios, unverified methods are also available:
//! ```rust,no_run
//! # use willow_sdk::WillowClient;
//! # async fn example(client: &WillowClient) -> Result<(), Box<dyn std::error::Error>> {
//! let data = client.data().get_unverified("dataset", "key").await?;
//! # Ok(())
//! # }
//! ```

pub mod auth;
pub mod client;
pub mod consensus;
pub mod data;
pub mod erc8004;
pub mod errors;
pub mod files;
pub mod indexers;
pub mod indexing;
pub mod light_client;
pub mod privacy;
pub mod proof;
pub mod registration;
pub mod subgrove_config;
pub mod token;
pub mod types;
pub mod utils;
pub mod validators;

pub use client::WillowClient;
pub use consensus::{ConsensusClient, Transaction};
pub use data::{
    CheckpointInfo, DataOperations, HistoricalQueryRequest, HistoricalQueryResponse, QueryResponse,
};
pub use errors::{Result, WillowError};
pub use indexers::{QuerySource, RoutedQueryResult, ServedBy, WillowIndexers};
pub use indexing::IndexingOperations;
#[cfg(not(feature = "no-light-client"))]
pub use light_client::{
    LightClient, LightClientConfig, LightClientConfigBuilder, TrustedHeader, TrustedState,
};
pub use proof::{ProofVerifier, QueryResponseExt};
pub use registration::RegistrationOperations;
pub use token::TokenOperations;
pub use willow_types::token::units as token_units;
pub use types::{
    ApiResponse, BalanceInfo, BlockVerificationStatus, DidDocument,
    DidPermissions, EthereumAnchor, FeeSchedule, GraphQLError, GraphQLRequest, GraphQLResponse,
    HealthStatus, IndexDefinition, IndexerInfo, IndexerStatus, MerkleProof, PathQueryData,
    PublicKey, QueryProof, RegisterSubgroveRequest, SchemaDefinition,
    SchemaField, SignatureAlgorithm, SignedRequestHeaders, StakeRequest, StoreDataRequest,
    SubgroveBalanceInfo, SubgroveIndexingStatus, SubgroveInfo, SubgroveRegistration,
    SubgroveStatus, TokenInfo, TransferRequest, UnstakeRequest, ValidatorInfo, VerificationStats,
    SqlRequest, SqlResponse, VerifyProofRequest, VerifyProofResponse,
};
pub use privacy::{PrivacyOperations, PrivacyConfig, CommitmentFrequency, EncryptedKeyGrant};
pub use subgrove_config::SubgroveDefinition;
pub use validators::ValidatorOperations;
pub use erc8004::{
    AgentReputationSummary, DisputeStats, Erc8004AgentListItem,
    Erc8004AgentListResponse, Erc8004Client, Erc8004ValidationRecord,
    Erc8004ValidationStatusResponse, Erc8004ValidationSummary, ReputationAttestation,
    ReputationHistoryEvent, ReputationHistoryResponse, ValidationStatusBreakdown,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Devnet validator accounts for local development.
///
/// These are the validator accounts pre-registered and funded in the devnet genesis.
/// Each validator has staked tokens (100,000 WILL) plus available balance (100,000 WILL)
/// for testing. Use them for SDK testing and development - DO NOT use in production!
///
/// # Example
///
/// ```rust,no_run
/// use willow_sdk::{WillowClient, DEVNET_VALIDATOR_1};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = WillowClient::new("http://localhost:3031").await?;
///
///     // Set identity for per-request signing
///     client.set_identity(
///         DEVNET_VALIDATOR_1.did,
///         DEVNET_VALIDATOR_1.private_key,
///         DEVNET_VALIDATOR_1.public_key_id
///     );
///
///     Ok(())
/// }
/// ```
pub mod devnet {
    /// Devnet validator account credentials
    pub struct ValidatorAccount {
        /// DID of the validator
        pub did: &'static str,
        /// Private key (hex) - DO NOT USE IN PRODUCTION
        pub private_key: &'static str,
        /// Public key (hex)
        pub public_key: &'static str,
        /// Key ID for authentication
        pub public_key_id: &'static str,
    }

    /// Validator 1 account for local devnet development.
    /// Has 100,000 WILL staked + 100,000 WILL available for testing.
    pub const VALIDATOR_1: ValidatorAccount = ValidatorAccount {
        did: "did:willow:validator1",
        private_key: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        public_key_id: "did:willow:validator1#key-1",
    };
}

/// Devnet validator 1 account for local development.
/// See [`devnet::VALIDATOR_1`] for usage details.
pub use devnet::VALIDATOR_1 as DEVNET_VALIDATOR_1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
