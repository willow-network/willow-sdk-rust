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
//! use willow_sdk::{WillowClient, auth::generate_did, types::SignatureAlgorithm};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create client
//!     let client = WillowClient::new("http://localhost:3031").await?;
//!
//!     // Generate DID
//!     let did_info = generate_did(SignatureAlgorithm::Ed25519)?;
//!
//!     // Authenticate
//!     client.authenticate(
//!         &did_info.did,
//!         &did_info.private_key_hex(),
//!         &did_info.public_key_id
//!     ).await?;
//!
//!     // All data operations are automatically verified against consensus
//!     let data = client.data().get("app_id", "dataset", "key").await?;
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
//! let data = client.data().get_unverified("app_id", "dataset", "key").await?;
//! # Ok(())
//! # }
//! ```

pub mod auth;
pub mod client;
pub mod consensus;
pub mod data;
pub mod errors;
pub mod indexing;
pub mod light_client;
pub mod proof;
pub mod registration;
pub mod token;
pub mod types;
pub mod utils;
pub mod validators;

// Re-export main types
pub use client::WillowClient;
pub use consensus::{ConsensusClient, Transaction};
pub use data::{DataOperations, QueryResponse};
pub use errors::{WillowError, Result};
pub use indexing::IndexingOperations;
#[cfg(not(feature = "no-light-client"))]
pub use light_client::{
    LightClient, LightClientConfig, LightClientConfigBuilder, TrustedHeader, TrustedState,
};
pub use proof::{ProofVerifier, QueryResponseExt};
pub use registration::RegistrationOperations;
pub use token::TokenOperations;
pub use types::{
    ApiResponse, AppRegistration, BalanceInfo, BlockVerificationStatus, DidDocument,
    DidPermissions, EthereumAnchor, FeeSchedule, GraphQLError, GraphQLRequest, GraphQLResponse,
    HealthStatus, IndexDefinition, IndexerInfo, IndexerStatus, MerkleProof, PathQueryData,
    PublicKey, QueryProof, RegisterAppRequest, RegisterSubgroveRequest, SchemaDefinition,
    SchemaField, Session, SignatureAlgorithm, StakeRequest, StoreDataRequest,
    SubgraphIndexingStatus, SubgraphInfo, SubgraphStatus, SubgroveRegistration, TokenInfo,
    TransferRequest, UnstakeRequest, ValidatorInfo, ValidatorStatus, VerificationStats,
    VerifyProofRequest, VerifyProofResponse,
};
pub use validators::ValidatorOperations;

// Version info
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Pre-funded test account for local devnet development.
///
/// This account is pre-registered and funded in the devnet genesis.
/// Use it for SDK testing and development - DO NOT use in production!
///
/// # Example
///
/// ```rust,no_run
/// use willow_sdk::{WillowClient, DEVNET_TEST_ACCOUNT};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = WillowClient::new("http://localhost:3031").await?;
///
///     // Authenticate with the pre-funded test account
///     client.authenticate(
///         DEVNET_TEST_ACCOUNT.did,
///         DEVNET_TEST_ACCOUNT.private_key,
///         DEVNET_TEST_ACCOUNT.public_key_id
///     ).await?;
///
///     Ok(())
/// }
/// ```
pub mod devnet {
    /// Pre-funded devnet test account credentials
    pub struct TestAccount {
        /// DID of the test account
        pub did: &'static str,
        /// Private key (hex) - DO NOT USE IN PRODUCTION
        pub private_key: &'static str,
        /// Public key (hex)
        pub public_key: &'static str,
        /// Key ID for authentication
        pub public_key_id: &'static str,
    }

    /// Pre-funded test account for local devnet development
    pub const TEST_ACCOUNT: TestAccount = TestAccount {
        did: "did:willow:devnet-test",
        private_key: "b5ecc03536f5e039e3c5bc46ad178d7faf80cee5f063016a4f4084e163409b3c",
        public_key: "c153874d3d284a11e3cb12b524e1a9cc32fef966d56b903c79688a95d5193c8f",
        public_key_id: "did:willow:devnet-test#key-1",
    };
}

/// Pre-funded test account for local devnet development.
/// See [`devnet::TEST_ACCOUNT`] for usage details.
pub use devnet::TEST_ACCOUNT as DEVNET_TEST_ACCOUNT;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
