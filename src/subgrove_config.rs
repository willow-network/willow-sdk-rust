//! Subgrove definition file loader for blockchain indexing.
//!
//! Loads TOML definition files that describe blockchain indexing subgroves.
//! Each file contains contract addresses, event signatures, schemas, and
//! configuration needed to register a subgrove via `RegisterSubgroveTx`.
//!
//! # Usage
//!
//! ```rust,no_run
//! use willow_sdk::subgrove_config::SubgroveDefinition;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let def = SubgroveDefinition::load("subgrove_definitions/ethereum/aave-v3.toml")?;
//!
//! // Register using the consensus client
//! let consensus = willow_sdk::consensus::ConsensusClient::new("http://localhost:26657");
//! let key_bytes = [0u8; 32];
//! let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
//! let tx_hash = consensus.register_blockchain_subgrove(
//!     &def,
//!     "did:willow:owner",
//!     "did:willow:owner#key-1",
//!     &signing_key,
//! ).await?;
//! # Ok(())
//! # }
//! ```

use serde::de;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::errors::{Result, WillowError};

/// Deserialize a u128 from either an integer or a quoted string.
/// TOML integers are i64, so values above i64::MAX must be quoted strings.
fn deserialize_u128<'de, D>(deserializer: D) -> std::result::Result<u128, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct U128Visitor;

    impl<'de> de::Visitor<'de> for U128Visitor {
        type Value = u128;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a u128 integer or string")
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<u128, E> {
            Ok(v as u128)
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<u128, E> {
            if v < 0 {
                Err(E::custom("negative value"))
            } else {
                Ok(v as u128)
            }
        }

        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<u128, E> {
            v.parse::<u128>().map_err(E::custom)
        }
    }

    deserializer.deserialize_any(U128Visitor)
}

/// A subgrove definition loaded from a TOML config file.
///
/// Contains everything needed to register a blockchain indexing subgrove,
/// except for runtime values (owner_did, signing credentials, nonce).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveDefinition {
    /// Unique identifier for the subgrove (e.g., "aave-v3-lending").
    pub subgrove_id: String,

    /// Human-readable description.
    pub description: String,

    /// Execution mode: "ConsensusExecution", "IndexerExecution", "TeeExecution", or "GkrExecution".
    #[serde(default = "default_execution_mode")]
    pub execution_mode: String,

    /// Sampling rate for IndexerExecution mode (0-50). Ignored for other modes.
    #[serde(default)]
    pub sampling_rate_percent: Option<u8>,

    /// TEE requirement for checkpoint verification.
    /// Absent or empty means no TEE required (optimistic-only).
    /// Set to "AwsNitro" or "IntelSgx" to require TEE attestation.
    #[serde(default)]
    pub required_tee: Option<String>,

    /// Indexer configuration.
    #[serde(default)]
    pub indexer_config: IndexerConfigDef,

    /// GraphQL schema defining the indexed entities (inline string).
    pub schema: String,

    /// Subgraph manifest describing data sources and event handlers.
    pub manifest: ManifestDef,
}

/// Indexer requirements and reward configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerConfigDef {
    #[serde(default = "default_min_indexers")]
    pub min_indexers: u8,
    #[serde(default = "default_max_indexers")]
    pub max_indexers: u8,
    #[serde(default = "default_reward_per_epoch", deserialize_with = "deserialize_u128")]
    pub reward_per_epoch: u128,
    #[serde(
        default = "default_min_indexer_stake",
        deserialize_with = "deserialize_u128"
    )]
    pub min_indexer_stake: u128,
}

impl Default for IndexerConfigDef {
    fn default() -> Self {
        Self {
            min_indexers: default_min_indexers(),
            max_indexers: default_max_indexers(),
            reward_per_epoch: default_reward_per_epoch(),
            min_indexer_stake: default_min_indexer_stake(),
        }
    }
}

/// Subgraph manifest describing what to index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestDef {
    pub spec_version: String,
    pub description: String,
    pub data_sources: Vec<DataSourceDef>,
}

/// A single data source (contract) to index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSourceDef {
    pub kind: String,
    pub name: String,
    pub network: String,
    pub source: SourceDef,
    pub mapping: MappingDef,
}

/// Contract address and deployment info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDef {
    pub address: String,
    pub abi: String,
    pub start_block: u64,
}

/// Event handler mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingDef {
    pub event_handlers: Vec<EventHandlerDef>,
}

/// A single event handler definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventHandlerDef {
    pub event: String,
    pub handler: String,
}

// Default value functions

fn default_execution_mode() -> String {
    "ConsensusExecution".to_string()
}

fn default_min_indexers() -> u8 {
    1
}

fn default_max_indexers() -> u8 {
    3
}

fn default_reward_per_epoch() -> u128 {
    100_000_000_000_000_000 // 0.1 WILL
}

fn default_min_indexer_stake() -> u128 {
    100_000_000_000_000_000_000_000 // 100k WILL
}

impl SubgroveDefinition {
    /// Load a subgrove definition from a TOML file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            WillowError::Custom(format!(
                "Failed to read subgrove definition file {}: {}",
                path.as_ref().display(),
                e
            ))
        })?;
        Self::from_toml(&content)
    }

    /// Parse a subgrove definition from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content)
            .map_err(|e| WillowError::Custom(format!("Failed to parse TOML: {}", e)))
    }

    /// Build the execution mode JSON value for the transaction.
    pub fn execution_mode_json(&self) -> serde_json::Value {
        match self.execution_mode.as_str() {
            "IndexerExecution" => serde_json::json!({
                "IndexerExecution": {
                    "sampling_rate_percent": self.sampling_rate_percent.unwrap_or(5)
                }
            }),
            "TeeExecution" => serde_json::json!({
                "TeeExecution": {
                    "tee_type": "AwsNitro"
                }
            }),
            "GkrExecution" => serde_json::json!("GkrExecution"),
            _ => serde_json::json!("ConsensusExecution"),
        }
    }

    /// Build the checkpoint verification config JSON value.
    pub fn checkpoint_verification_json(&self) -> serde_json::Value {
        match &self.required_tee {
            Some(tee_type) => serde_json::json!({
                "required_tee": tee_type
            }),
            None => serde_json::json!({
                "required_tee": null
            }),
        }
    }

    /// Build the complete `RegisterSubgrove` transaction JSON.
    ///
    /// The returned value can be submitted directly via
    /// `ConsensusClient::submit_raw_transaction()`.
    pub fn to_register_transaction(
        &self,
        owner_did: &str,
        public_key_id: &str,
        signature: Vec<u8>,
        nonce: u64,
    ) -> String {
        use willow_types::consensus::transactions::RegisterSubgroveTx;
        use willow_types::consensus::indexing_transactions::{
            SubgroveMode, ExecutionMode, IndexerConfig, RetentionWindow,
        };

        let manifest_content = serde_json::to_vec(&self.manifest).unwrap_or_default();

        let execution_mode = match self.execution_mode.as_str() {
            "IndexerExecution" => ExecutionMode::IndexerExecution {
                sampling_rate_percent: self.sampling_rate_percent.unwrap_or(5),
            },
            "TeeExecution" => ExecutionMode::TeeExecution {
                tee_type: willow_types::tee::TeeType::AwsNitro,
            },
            "GkrExecution" => ExecutionMode::GkrExecution,
            _ => ExecutionMode::ConsensusExecution,
        };

        let indexer_config = IndexerConfig {
            min_indexers: self.indexer_config.min_indexers,
            max_indexers: self.indexer_config.max_indexers,
            reward_per_epoch: self.indexer_config.reward_per_epoch,
            epoch_length: 100,
            min_indexer_stake: self.indexer_config.min_indexer_stake,
        };

        let register_tx = RegisterSubgroveTx {
            subgrove_id: self.subgrove_id.clone(),
            name: self.subgrove_id.clone(),
            description: self.description.clone(),
            schema: self.schema.clone(),
            owner_did: owner_did.to_string(),
            admins: vec![],
            initial_funding: None,
            mode: SubgroveMode::BlockchainIndexing {
                manifest_content,
                wasm_modules: vec![],
                execution_mode,
                indexer_config,
                retention_window: RetentionWindow::default(),
            },
            checkpoint_verification: Default::default(),
            privacy: None,
            initial_owner_key_grant: None,
            signature,
            public_key_id: public_key_id.to_string(),
            nonce,
        };

        crate::consensus::ConsensusClient::serialize_tx("RegisterSubgrove", &register_tx)
            .unwrap_or_default()
    }

    /// Build the canonical signing payload for BlockchainIndexing subgroves.
    ///
    /// Format: `RegisterSubgrove:{subgrove_id}:{owner_did}:{nonce}`
    pub fn signing_payload(&self, owner_did: &str, nonce: u64) -> String {
        format!(
            "RegisterSubgrove:{}:{}:{}",
            self.subgrove_id, owner_did, nonce
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
subgrove_id = "test-swaps"
description = "Test swap events"
execution_mode = "ConsensusExecution"

schema = """
type Swap @entity {
  id: ID!
  sender: String!
  amount: BigInt!
}
"""

[indexer_config]
min_indexers = 1
max_indexers = 3
reward_per_epoch = "100000000000000000"
min_indexer_stake = "100000000000000000000000"

[manifest]
spec_version = "0.0.4"
description = "Test Swaps"

[[manifest.data_sources]]
kind = "ethereum/contract"
name = "TestPool"
network = "mainnet"

[manifest.data_sources.source]
address = "0x1234567890abcdef1234567890abcdef12345678"
abi = "TestPool"
start_block = 12345678

[[manifest.data_sources.mapping.event_handlers]]
event = "Swap(address,address,int256)"
handler = "handleSwap"
"#;

    #[test]
    fn test_parse_toml() {
        let def = SubgroveDefinition::from_toml(SAMPLE_TOML).unwrap();
        assert_eq!(def.subgrove_id, "test-swaps");
        assert_eq!(def.description, "Test swap events");
        assert_eq!(def.execution_mode, "ConsensusExecution");
        assert_eq!(def.manifest.data_sources.len(), 1);
        assert_eq!(def.manifest.data_sources[0].name, "TestPool");
        assert_eq!(
            def.manifest.data_sources[0].source.address,
            "0x1234567890abcdef1234567890abcdef12345678"
        );
        assert_eq!(def.manifest.data_sources[0].source.start_block, 12345678);
        assert_eq!(
            def.manifest.data_sources[0].mapping.event_handlers.len(),
            1
        );
    }

    #[test]
    fn test_signing_payload() {
        let def = SubgroveDefinition::from_toml(SAMPLE_TOML).unwrap();
        let payload = def.signing_payload("did:willow:owner", 1);
        assert_eq!(
            payload,
            "RegisterSubgrove:test-swaps:did:willow:owner:1"
        );
    }

    #[test]
    fn test_to_register_transaction() {
        let def = SubgroveDefinition::from_toml(SAMPLE_TOML).unwrap();
        let tx = def.to_register_transaction(
            "did:willow:owner",
            "did:willow:owner#key-1",
            vec![1, 2, 3],
            1,
        );
        let parsed: serde_json::Value = serde_json::from_str(&tx).unwrap();
        let reg = &parsed["RegisterSubgrove"];
        assert_eq!(reg["subgrove_id"], "test-swaps");
        assert_eq!(reg["owner_did"], "did:willow:owner");
        assert!(reg["mode"]["BlockchainIndexing"].is_object());
    }

    #[test]
    fn test_defaults() {
        let minimal_toml = r#"
subgrove_id = "minimal"
description = "Minimal definition"
schema = "type T @entity { id: ID! }"

[manifest]
spec_version = "0.0.4"
description = "Minimal"

[[manifest.data_sources]]
kind = "ethereum/contract"
name = "Test"
network = "mainnet"

[manifest.data_sources.source]
address = "0x0000000000000000000000000000000000000000"
abi = "Test"
start_block = 1

[[manifest.data_sources.mapping.event_handlers]]
event = "Event()"
handler = "handle"
"#;
        let def = SubgroveDefinition::from_toml(minimal_toml).unwrap();
        assert_eq!(def.execution_mode, "ConsensusExecution");
        assert!(def.required_tee.is_none());
        assert_eq!(def.indexer_config.min_indexers, 1);
        assert_eq!(def.indexer_config.max_indexers, 3);
    }

    #[test]
    fn test_indexer_execution_mode() {
        let toml_str = r#"
subgrove_id = "ie-test"
description = "IndexerExecution test"
execution_mode = "IndexerExecution"
sampling_rate_percent = 10
schema = "type T @entity { id: ID! }"

[manifest]
spec_version = "0.0.4"
description = "Test"

[[manifest.data_sources]]
kind = "ethereum/contract"
name = "Test"
network = "mainnet"

[manifest.data_sources.source]
address = "0x0000000000000000000000000000000000000000"
abi = "Test"
start_block = 1

[[manifest.data_sources.mapping.event_handlers]]
event = "Event()"
handler = "handle"
"#;
        let def = SubgroveDefinition::from_toml(toml_str).unwrap();
        let mode = def.execution_mode_json();
        assert_eq!(mode["IndexerExecution"]["sampling_rate_percent"], 10);
    }
}
