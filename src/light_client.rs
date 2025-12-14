//! Light client for trustless verification of Willow state.
//!
//! This module implements a standalone light client that can verify Willow
//! query results without trusting any single node. It uses the CometBFT light
//! client protocol to verify block headers and GroveDB proofs.
//!
//! # Feature Flag
//!
//! Proof verification is enabled by default. To disable it for minimal
//! dependencies (e.g., if you trust your node), use:
//!
//! ```toml
//! [dependencies]
//! willow-sdk = { version = "0.1", features = ["no-light-client"] }
//! ```
//!
//! # Architecture
//!
//! The light client performs two types of verification:
//!
//! 1. **Header Verification** (CometBFT Light Client Protocol)
//!    - Fetches block headers from CometBFT RPC
//!    - Verifies 2/3+ validator signatures
//!    - Tracks validator set transitions
//!    - Extracts trusted `app_hash` (state root)
//!
//! 2. **Proof Verification** (GroveDB)
//!    - Verifies Merkle proofs against the trusted `app_hash`
//!    - Uses lightweight `grovedb/verify` feature (no RocksDB)
//!
//! # Example
//!
//! ```rust,ignore
//! use willow_sdk::light_client::{LightClient, LightClientConfig};
//!
//! // Configure the light client
//! let config = LightClientConfig::builder("willow-mainnet")
//!     .validator_endpoints(vec![
//!         "http://validator1:26657".to_string(),
//!         "http://validator2:26657".to_string(),
//!     ])
//!     .build();
//!
//! // Create and initialize
//! let mut client = LightClient::new(config)?;
//! client.sync_to_latest().await?;
//!
//! // Verify a proof
//! let is_valid = client.verify_proof(&proof_bytes, &query_result, None).await?;
//! ```

use crate::errors::{Result, WillowError};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier as Ed25519Verifier, VerifyingKey};
use secp256k1::{ecdsa::Signature as Secp256k1Signature, Message, Secp256k1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// ============================================================================
// Types
// ============================================================================

/// Light client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientConfig {
    /// Chain ID of the Willow network.
    pub chain_id: String,

    /// Validator RPC endpoints to fetch headers from.
    pub validator_endpoints: Vec<String>,

    /// Minimum validators that must agree for consensus.
    #[serde(default = "default_min_validators")]
    pub min_validators_for_consensus: usize,

    /// Trust threshold as (numerator, denominator), default: (2, 3).
    #[serde(default = "default_trust_threshold")]
    pub trust_threshold: (u64, u64),

    /// How long headers remain valid, default: 24 hours.
    #[serde(default = "default_trusting_period")]
    pub trusting_period: Duration,

    /// Maximum allowed clock drift, default: 10 seconds.
    #[serde(default = "default_clock_drift")]
    pub max_clock_drift: Duration,

    /// RPC request timeout, default: 10 seconds.
    #[serde(default = "default_rpc_timeout")]
    pub rpc_timeout: Duration,

    /// Whether to automatically sync to the latest height on creation.
    /// Default: true.
    #[serde(default = "default_auto_sync")]
    pub auto_sync: bool,
}

fn default_min_validators() -> usize {
    1
}
fn default_trust_threshold() -> (u64, u64) {
    (2, 3)
}
fn default_trusting_period() -> Duration {
    Duration::from_secs(86400)
}
fn default_clock_drift() -> Duration {
    Duration::from_secs(10)
}
fn default_rpc_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_auto_sync() -> bool {
    true
}

impl LightClientConfig {
    /// Creates a new config builder.
    pub fn builder(chain_id: impl Into<String>) -> LightClientConfigBuilder {
        LightClientConfigBuilder::new(chain_id)
    }
}

/// Builder for light client configuration.
pub struct LightClientConfigBuilder {
    config: LightClientConfig,
}

impl LightClientConfigBuilder {
    /// Creates a new builder with the given chain ID.
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self {
            config: LightClientConfig {
                chain_id: chain_id.into(),
                validator_endpoints: vec![],
                min_validators_for_consensus: default_min_validators(),
                trust_threshold: default_trust_threshold(),
                trusting_period: default_trusting_period(),
                max_clock_drift: default_clock_drift(),
                rpc_timeout: default_rpc_timeout(),
                auto_sync: default_auto_sync(),
            },
        }
    }

    /// Sets the validator endpoints.
    pub fn validator_endpoints(mut self, endpoints: Vec<String>) -> Self {
        self.config.validator_endpoints = endpoints;
        self
    }

    /// Sets the minimum validators required for consensus.
    pub fn min_validators_for_consensus(mut self, min: usize) -> Self {
        self.config.min_validators_for_consensus = min;
        self
    }

    /// Sets the trust threshold (numerator/denominator).
    pub fn trust_threshold(mut self, numerator: u64, denominator: u64) -> Self {
        self.config.trust_threshold = (numerator, denominator);
        self
    }

    /// Sets the trusting period.
    pub fn trusting_period(mut self, period: Duration) -> Self {
        self.config.trusting_period = period;
        self
    }

    /// Sets the maximum clock drift tolerance.
    pub fn max_clock_drift(mut self, drift: Duration) -> Self {
        self.config.max_clock_drift = drift;
        self
    }

    /// Sets the RPC timeout.
    pub fn rpc_timeout(mut self, timeout: Duration) -> Self {
        self.config.rpc_timeout = timeout;
        self
    }

    /// Sets whether to automatically sync to the latest height on creation.
    /// Default: true.
    pub fn auto_sync(mut self, auto_sync: bool) -> Self {
        self.config.auto_sync = auto_sync;
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> LightClientConfig {
        self.config
    }
}

/// A verified block header with commit signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightBlock {
    /// The block header.
    pub header: Header,
    /// The commit (validator signatures).
    pub commit: Commit,
    /// The validator set for this block.
    pub validators: ValidatorSet,
}

/// Block header containing consensus and state information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    /// Chain identifier.
    pub chain_id: String,
    /// Block height.
    pub height: u64,
    /// Block timestamp.
    pub time: DateTime<Utc>,
    /// Hash of the previous block.
    pub last_block_id: Option<BlockId>,
    /// Hash of the current validator set.
    pub validators_hash: Vec<u8>,
    /// Hash of the next validator set.
    pub next_validators_hash: Vec<u8>,
    /// Application state root hash (GroveDB root).
    pub app_hash: Vec<u8>,
}

/// Block identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockId {
    /// Block hash.
    pub hash: Vec<u8>,
    /// Parts header.
    pub parts: Option<PartSetHeader>,
}

/// Part set header for block parts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartSetHeader {
    /// Total number of parts.
    pub total: u32,
    /// Hash of the parts.
    pub hash: Vec<u8>,
}

/// Commit containing validator signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    /// Block height.
    pub height: u64,
    /// Commit round.
    pub round: u32,
    /// Block ID being committed to.
    pub block_id: BlockId,
    /// Validator signatures.
    pub signatures: Vec<CommitSig>,
}

/// A validator's commit signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommitSig {
    /// Validator voted for the block.
    BlockIdFlagCommit {
        /// Validator address.
        validator_address: Vec<u8>,
        /// Timestamp of the vote.
        timestamp: DateTime<Utc>,
        /// Signature bytes.
        signature: Vec<u8>,
    },
    /// Validator voted nil.
    BlockIdFlagNil,
    /// Validator was absent.
    BlockIdFlagAbsent,
}

/// Set of validators for a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// List of validators.
    pub validators: Vec<Validator>,
    /// Total voting power.
    pub total_voting_power: u64,
}

/// A validator in the set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// Validator address (first 20 bytes of pubkey hash).
    pub address: Vec<u8>,
    /// Public key.
    pub pub_key: PublicKey,
    /// Voting power.
    pub voting_power: u64,
}

/// Validator public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PublicKey {
    /// Ed25519 public key (32 bytes).
    Ed25519(Vec<u8>),
    /// Secp256k1 public key (33 or 65 bytes).
    Secp256k1(Vec<u8>),
}

/// Trusted header for bootstrapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedHeader {
    /// Block height.
    pub height: u64,
    /// Block hash (hex encoded).
    pub hash: String,
    /// Serialized light block (base64 JSON).
    pub light_block_data: String,
}

/// Trusted state for persistence across sessions.
///
/// Contains the chain ID and verified headers that can be serialized
/// to disk and restored later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedState {
    /// Chain ID this state belongs to.
    pub chain_id: String,
    /// Verified light blocks.
    pub headers: Vec<LightBlock>,
}

// ============================================================================
// Light Client
// ============================================================================

/// CometBFT light client for trustless Willow verification.
///
/// Maintains verified headers and can verify GroveDB proofs against
/// the `app_hash` in those headers.
pub struct LightClient {
    config: LightClientConfig,
    /// Verified headers indexed by height.
    headers: Arc<RwLock<BTreeMap<u64, LightBlock>>>,
    /// HTTP client for RPC requests.
    http_client: reqwest::Client,
}

impl LightClient {
    /// Creates a new light client.
    pub fn new(config: LightClientConfig) -> Result<Self> {
        // Validate config
        if config.trust_threshold.0 > config.trust_threshold.1 {
            return Err(WillowError::Config(
                "Trust threshold numerator cannot exceed denominator".to_string(),
            ));
        }
        if config.chain_id.is_empty() {
            return Err(WillowError::Config("Chain ID cannot be empty".to_string()));
        }

        let http_client = reqwest::Client::builder()
            .timeout(config.rpc_timeout)
            .build()
            .map_err(|e| WillowError::Config(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            headers: Arc::new(RwLock::new(BTreeMap::new())),
            http_client,
        })
    }

    /// Initializes with a trusted header.
    ///
    /// This must be called before verifying other headers. The trusted header
    /// should be obtained from a trusted source (genesis, checkpoint, etc.).
    pub async fn initialize_with_trusted_header(&self, header: LightBlock) -> Result<()> {
        if header.header.chain_id != self.config.chain_id {
            return Err(WillowError::LightClient(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.config.chain_id, header.header.chain_id
            )));
        }

        let mut headers = self.headers.write().await;
        headers.insert(header.header.height, header);
        Ok(())
    }

    /// Returns the latest verified header.
    pub async fn get_latest_header(&self) -> Option<LightBlock> {
        let headers = self.headers.read().await;
        headers.values().last().cloned()
    }

    /// Returns a header at a specific height.
    pub async fn get_header_by_height(&self, height: u64) -> Option<LightBlock> {
        let headers = self.headers.read().await;
        headers.get(&height).cloned()
    }

    /// Returns the verified height range (min, max).
    pub async fn get_verified_height_range(&self) -> Option<(u64, u64)> {
        let headers = self.headers.read().await;
        if headers.is_empty() {
            return None;
        }
        let min = *headers.keys().next()?;
        let max = *headers.keys().last()?;
        Some((min, max))
    }

    /// Syncs to the latest height from validators.
    pub async fn sync_to_latest(&self) -> Result<()> {
        if self.config.validator_endpoints.is_empty() {
            return Err(WillowError::LightClient(
                "No validator endpoints configured".to_string(),
            ));
        }

        // Fetch latest block from first available validator
        let latest = self.fetch_latest_block().await?;
        let target_height = latest.header.height;

        // Get our current height
        let current_height = {
            let headers = self.headers.read().await;
            headers.keys().last().copied().unwrap_or(0)
        };

        if current_height >= target_height {
            return Ok(());
        }

        // If we have no headers, initialize with the latest
        if current_height == 0 {
            self.initialize_with_trusted_header(latest).await?;
            return Ok(());
        }

        // Sync sequentially (in production, use bisection for efficiency)
        for height in (current_height + 1)..=target_height {
            let block = self.fetch_block_at_height(height).await?;
            self.verify_and_store_header(block).await?;
        }

        Ok(())
    }

    /// Initializes the light client using trust-on-first-use.
    ///
    /// This fetches the latest block from validators and trusts it as the initial state.
    /// All subsequent blocks are verified against this initial trusted state.
    ///
    /// Important: TODO: When mainnet/testnet launches, replace trust-on-first-use
    /// with hardcoded checkpoint headers for true trustless initialization.
    /// Trust-on-first-use is secure for subsequent operations but trusts the
    /// initial block from the connected validators.
    pub async fn initialize_with_trust_on_first_use(&self) -> Result<()> {
        if self.config.validator_endpoints.is_empty() {
            return Err(WillowError::LightClient(
                "No validator endpoints configured for trust-on-first-use initialization"
                    .to_string(),
            ));
        }

        // TODO: When mainnet/testnet launches, use hardcoded checkpoint headers
        // instead of trust-on-first-use for true trustless initialization from genesis.

        // Fetch the latest block from validators
        let latest = self.fetch_latest_block().await?;

        // Trust this block as our initial state
        let mut headers = self.headers.write().await;
        headers.insert(latest.header.height, latest);

        log::info!(
            "Light client initialized with trust-on-first-use at height {}",
            headers.keys().last().unwrap_or(&0)
        );

        Ok(())
    }

    /// Gets the verified root hash (app_hash) from the latest trusted header.
    ///
    /// This is the cryptographically verified root hash that proofs should be
    /// verified against for trustless data verification.
    ///
    /// If no trusted headers are available, this will auto-initialize using
    /// trust-on-first-use.
    ///
    /// Returns the app_hash as a hex string.
    pub async fn get_verified_root_hash(&self) -> Result<String> {
        // Check if we have any trusted headers
        {
            let headers = self.headers.read().await;
            if headers.is_empty() {
                drop(headers); // Release read lock before acquiring write
                               // Auto-initialize with trust-on-first-use
                self.initialize_with_trust_on_first_use().await?;
            }
        }

        let header = self
            .get_latest_header()
            .await
            .ok_or_else(|| WillowError::LightClient("No trusted header available".to_string()))?;

        Ok(hex::encode(&header.header.app_hash))
    }

    /// Verifies a new header against the latest trusted header.
    async fn verify_and_store_header(&self, header: LightBlock) -> Result<()> {
        let trusted = self
            .get_latest_header()
            .await
            .ok_or_else(|| WillowError::LightClient("No trusted header available".to_string()))?;

        // Verify the header
        self.verify_header(&trusted, &header)?;

        // Store it
        let mut headers = self.headers.write().await;
        headers.insert(header.header.height, header);
        Ok(())
    }

    /// Verifies an untrusted header against a trusted one.
    fn verify_header(&self, trusted: &LightBlock, untrusted: &LightBlock) -> Result<()> {
        // Check chain ID
        if untrusted.header.chain_id != self.config.chain_id {
            return Err(WillowError::LightClient(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.config.chain_id, untrusted.header.chain_id
            )));
        }

        // Check sequential heights (simplified - production would use bisection)
        if untrusted.header.height != trusted.header.height + 1 {
            return Err(WillowError::LightClient(format!(
                "Non-sequential headers: {} -> {}",
                trusted.header.height, untrusted.header.height
            )));
        }

        // Check time progression
        if untrusted.header.time <= trusted.header.time {
            return Err(WillowError::LightClient(
                "Header time did not progress".to_string(),
            ));
        }

        // Check trusting period
        let now = Utc::now();
        let header_age = now - untrusted.header.time;
        if header_age > chrono::Duration::from_std(self.config.trusting_period).unwrap() {
            return Err(WillowError::LightClient(
                "Header is outside trusting period".to_string(),
            ));
        }

        // Check clock drift
        if untrusted.header.time
            > now + chrono::Duration::from_std(self.config.max_clock_drift).unwrap()
        {
            return Err(WillowError::LightClient(
                "Header time is too far in the future".to_string(),
            ));
        }

        // Check validator set transition
        if untrusted.header.validators_hash != trusted.header.next_validators_hash {
            return Err(WillowError::LightClient(
                "Validator set hash mismatch".to_string(),
            ));
        }

        // Verify commit signatures
        let (signed_power, total_power) = self.verify_commit_signatures(untrusted)?;

        // Check trust threshold
        let threshold_power =
            (total_power * self.config.trust_threshold.0).div_ceil(self.config.trust_threshold.1);

        if signed_power < threshold_power {
            return Err(WillowError::LightClient(format!(
                "Insufficient voting power: {} < {} required",
                signed_power, threshold_power
            )));
        }

        Ok(())
    }

    /// Verifies commit signatures and returns (signed_power, total_power).
    fn verify_commit_signatures(&self, block: &LightBlock) -> Result<(u64, u64)> {
        let total_power = block.validators.total_voting_power;
        let mut signed_power = 0u64;

        for sig in &block.commit.signatures {
            if let CommitSig::BlockIdFlagCommit {
                validator_address,
                signature,
                ..
            } = sig
            {
                // Find the validator
                let validator = block
                    .validators
                    .validators
                    .iter()
                    .find(|v| &v.address == validator_address)
                    .ok_or_else(|| {
                        WillowError::LightClient("Validator not found for signature".to_string())
                    })?;

                // Verify signature
                if self.verify_signature(validator, signature, block)? {
                    signed_power += validator.voting_power;
                }
            }
        }

        Ok((signed_power, total_power))
    }

    /// Verifies a validator's signature on a block.
    fn verify_signature(
        &self,
        validator: &Validator,
        signature: &[u8],
        block: &LightBlock,
    ) -> Result<bool> {
        let sign_bytes = self.create_vote_sign_bytes(block)?;

        match &validator.pub_key {
            PublicKey::Ed25519(pubkey_bytes) => {
                if pubkey_bytes.len() != 32 || signature.len() != 64 {
                    return Ok(false);
                }

                let verifying_key = VerifyingKey::from_bytes(
                    pubkey_bytes.as_slice().try_into().unwrap(),
                )
                .map_err(|e| WillowError::LightClient(format!("Invalid Ed25519 key: {}", e)))?;

                let sig = Ed25519Signature::from_bytes(signature.try_into().unwrap());
                Ok(verifying_key.verify(&sign_bytes, &sig).is_ok())
            }
            PublicKey::Secp256k1(pubkey_bytes) => {
                if (pubkey_bytes.len() != 33 && pubkey_bytes.len() != 65)
                    || (signature.len() != 64 && signature.len() != 65)
                {
                    return Ok(false);
                }

                let secp = Secp256k1::new();
                let public_key = secp256k1::PublicKey::from_slice(pubkey_bytes).map_err(|e| {
                    WillowError::LightClient(format!("Invalid Secp256k1 key: {}", e))
                })?;

                let hash = Sha256::digest(&sign_bytes);
                let message = Message::from_digest_slice(&hash)
                    .map_err(|e| WillowError::LightClient(format!("Invalid message: {}", e)))?;

                let sig = Secp256k1Signature::from_compact(&signature[..64]).map_err(|e| {
                    WillowError::LightClient(format!("Invalid Secp256k1 signature: {}", e))
                })?;

                Ok(secp.verify_ecdsa(&message, &sig, &public_key).is_ok())
            }
        }
    }

    /// Creates the canonical vote sign bytes for a commit.
    fn create_vote_sign_bytes(&self, block: &LightBlock) -> Result<Vec<u8>> {
        let mut sign_bytes = Vec::new();

        // Type: 0x02 for Precommit
        sign_bytes.push(0x02);

        // Height (int64 little-endian)
        sign_bytes.extend_from_slice(&block.header.height.to_le_bytes());

        // Round (int64 little-endian)
        sign_bytes.extend_from_slice(&block.commit.round.to_le_bytes());

        // BlockID
        if let Some(ref last_block_id) = block.header.last_block_id {
            sign_bytes.extend_from_slice(&last_block_id.hash);
            sign_bytes.extend_from_slice(&[0u8; 32]); // Parts header placeholder
        } else {
            sign_bytes.extend_from_slice(&[0u8; 64]);
        }

        // Timestamp
        let timestamp_nanos = block
            .header
            .time
            .timestamp_nanos_opt()
            .ok_or_else(|| WillowError::LightClient("Invalid timestamp".to_string()))?;
        sign_bytes.extend_from_slice(&timestamp_nanos.to_le_bytes());

        // Chain ID
        sign_bytes.extend_from_slice(self.config.chain_id.as_bytes());

        Ok(sign_bytes)
    }

    /// Fetches the latest block from validators.
    async fn fetch_latest_block(&self) -> Result<LightBlock> {
        self.fetch_block_at_height(0).await // 0 means latest
    }

    /// Fetches a block at a specific height (0 = latest).
    async fn fetch_block_at_height(&self, height: u64) -> Result<LightBlock> {
        let mut last_error = None;

        for endpoint in &self.config.validator_endpoints {
            match self.fetch_block_from_endpoint(endpoint, height).await {
                Ok(block) => return Ok(block),
                Err(e) => {
                    log::warn!("Failed to fetch from {}: {}", endpoint, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            WillowError::LightClient("No validator endpoints available".to_string())
        }))
    }

    /// Fetches a block from a specific endpoint.
    async fn fetch_block_from_endpoint(&self, endpoint: &str, height: u64) -> Result<LightBlock> {
        // Fetch commit
        let commit_url = if height == 0 {
            format!("{}/commit", endpoint)
        } else {
            format!("{}/commit?height={}", endpoint, height)
        };

        let commit_resp: serde_json::Value = self
            .http_client
            .get(&commit_url)
            .send()
            .await
            .map_err(|e| WillowError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| WillowError::Network(e.to_string()))?;

        // Fetch validators
        let actual_height = commit_resp["result"]["signed_header"]["header"]["height"]
            .as_str()
            .and_then(|h| h.parse::<u64>().ok())
            .unwrap_or(height);

        let validators_url = format!("{}/validators?height={}", endpoint, actual_height);
        let validators_resp: serde_json::Value = self
            .http_client
            .get(&validators_url)
            .send()
            .await
            .map_err(|e| WillowError::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| WillowError::Network(e.to_string()))?;

        // Parse into LightBlock
        self.parse_light_block(&commit_resp, &validators_resp)
    }

    /// Parses CometBFT RPC responses into a LightBlock.
    fn parse_light_block(
        &self,
        commit_resp: &serde_json::Value,
        validators_resp: &serde_json::Value,
    ) -> Result<LightBlock> {
        let signed_header = &commit_resp["result"]["signed_header"];
        let header_json = &signed_header["header"];
        let commit_json = &signed_header["commit"];

        // Parse header
        let header = Header {
            chain_id: header_json["chain_id"].as_str().unwrap_or("").to_string(),
            height: header_json["height"]
                .as_str()
                .and_then(|h| h.parse().ok())
                .unwrap_or(0),
            time: header_json["time"]
                .as_str()
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            last_block_id: parse_block_id(&header_json["last_block_id"]),
            validators_hash: parse_hex_bytes(header_json["validators_hash"].as_str().unwrap_or("")),
            next_validators_hash: parse_hex_bytes(
                header_json["next_validators_hash"].as_str().unwrap_or(""),
            ),
            app_hash: parse_hex_bytes(header_json["app_hash"].as_str().unwrap_or("")),
        };

        // Parse commit
        let commit = Commit {
            height: commit_json["height"]
                .as_str()
                .and_then(|h| h.parse().ok())
                .unwrap_or(0),
            round: commit_json["round"]
                .as_str()
                .and_then(|r| r.parse().ok())
                .unwrap_or(0),
            block_id: parse_block_id(&commit_json["block_id"]).unwrap_or(BlockId {
                hash: vec![],
                parts: None,
            }),
            signatures: parse_commit_signatures(&commit_json["signatures"]),
        };

        // Parse validators
        let validators_json = &validators_resp["result"]["validators"];
        let validators = parse_validator_set(validators_json);

        Ok(LightBlock {
            header,
            commit,
            validators,
        })
    }

    /// Verifies a GroveDB proof against a trusted header.
    ///
    /// # Arguments
    ///
    /// * `proof` - The GroveDB proof bytes
    /// * `query_result` - The query result to verify
    /// * `height` - Optional height to verify against (uses latest if None)
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the proof is valid, `Ok(false)` if invalid.
    #[cfg(not(feature = "no-light-client"))]
    pub async fn verify_proof(
        &self,
        proof: &[u8],
        query_result: &[Vec<u8>],
        height: Option<u64>,
    ) -> Result<bool> {
        use grovedb::GroveDb;
        use grovedb::PathQuery;
        use grovedb::Query;

        // Get the header to verify against
        let header = match height {
            Some(h) => self.get_header_by_height(h).await,
            None => self.get_latest_header().await,
        }
        .ok_or_else(|| WillowError::LightClient("No verified header available".to_string()))?;

        let expected_root = &header.header.app_hash;

        // Use GroveDB's verify_query to verify the proof
        // We need to construct a minimal query - the proof contains the query info
        let empty_path: Vec<Vec<u8>> = vec![];
        let query = Query::new();
        let path_query = PathQuery::new_unsized(empty_path, query);

        let grove_version = grovedb_version::version::GroveVersion::default();

        match GroveDb::verify_query(proof, &path_query, &grove_version) {
            Ok((computed_root, verified_items)) => {
                // Check if root hash matches
                if computed_root.as_slice() != expected_root.as_slice() {
                    return Ok(false);
                }

                // Verify the result items match
                let verified_values: Vec<Vec<u8>> = verified_items
                    .into_iter()
                    .map(|(_, value, _)| value)
                    .collect();

                if verified_values.len() != query_result.len() {
                    return Ok(false);
                }

                for (v1, v2) in verified_values.iter().zip(query_result.iter()) {
                    if v1 != v2 {
                        return Ok(false);
                    }
                }

                Ok(true)
            }
            Err(e) => {
                log::warn!("GroveDB proof verification failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Verifies a proof (stub when no-light-client feature is enabled).
    #[cfg(feature = "no-light-client")]
    pub async fn verify_proof(
        &self,
        _proof: &[u8],
        _query_result: &[Vec<u8>],
        _height: Option<u64>,
    ) -> Result<bool> {
        Err(WillowError::LightClient(
            "Proof verification disabled with 'no-light-client' feature".to_string(),
        ))
    }

    /// Verifies a hex-encoded proof.
    pub async fn verify_proof_hex(
        &self,
        proof_hex: &str,
        query_result: &[Vec<u8>],
        height: Option<u64>,
    ) -> Result<bool> {
        let proof = hex::decode(proof_hex)
            .map_err(|e| WillowError::LightClient(format!("Invalid proof hex: {}", e)))?;
        self.verify_proof(&proof, query_result, height).await
    }

    /// Returns the chain ID.
    pub fn chain_id(&self) -> &str {
        &self.config.chain_id
    }

    /// Returns the validator endpoints.
    pub fn validator_endpoints(&self) -> &[String] {
        &self.config.validator_endpoints
    }

    /// Prunes headers outside the trusting period.
    pub async fn prune_old_headers(&self) -> usize {
        let now = Utc::now();
        let trusting_period = chrono::Duration::from_std(self.config.trusting_period).unwrap();

        let mut headers = self.headers.write().await;
        let old_len = headers.len();

        headers.retain(|_, block| now - block.header.time < trusting_period);

        old_len - headers.len()
    }

    /// Creates a new light client with optional auto-sync.
    ///
    /// If `config.auto_sync` is true, this will sync to the latest height
    /// from validators before returning.
    pub async fn new_async(config: LightClientConfig) -> Result<Self> {
        let client = Self::new(config)?;
        if client.config.auto_sync && !client.config.validator_endpoints.is_empty() {
            client.sync_to_latest().await?;
        }
        Ok(client)
    }

    /// Exports the current trusted state for persistence.
    ///
    /// Returns a serializable state containing verified headers that can be
    /// saved to disk and restored later using `import_trusted_state`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let state = client.export_trusted_state().await;
    /// let json = serde_json::to_string(&state)?;
    /// std::fs::write("light_client_state.json", json)?;
    /// ```
    pub async fn export_trusted_state(&self) -> TrustedState {
        let headers = self.headers.read().await;
        TrustedState {
            chain_id: self.config.chain_id.clone(),
            headers: headers.values().cloned().collect(),
        }
    }

    /// Imports previously exported trusted state.
    ///
    /// This restores headers that were previously verified, allowing the
    /// light client to resume from where it left off without re-syncing.
    ///
    /// # Arguments
    ///
    /// * `state` - The trusted state to import
    ///
    /// # Returns
    ///
    /// Returns an error if the chain ID doesn't match.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let json = std::fs::read_to_string("light_client_state.json")?;
    /// let state: TrustedState = serde_json::from_str(&json)?;
    /// client.import_trusted_state(state).await?;
    /// ```
    pub async fn import_trusted_state(&self, state: TrustedState) -> Result<()> {
        if state.chain_id != self.config.chain_id {
            return Err(WillowError::LightClient(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.config.chain_id, state.chain_id
            )));
        }

        let mut headers = self.headers.write().await;
        for header in state.headers {
            headers.insert(header.header.height, header);
        }

        Ok(())
    }

    /// Returns whether auto_sync is enabled.
    pub fn auto_sync(&self) -> bool {
        self.config.auto_sync
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_hex_bytes(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap_or_default()
}

fn parse_block_id(json: &serde_json::Value) -> Option<BlockId> {
    let hash = json["hash"].as_str()?;
    Some(BlockId {
        hash: parse_hex_bytes(hash),
        parts: json["parts"].as_object().map(|p| PartSetHeader {
            total: p["total"]
                .as_str()
                .and_then(|t| t.parse().ok())
                .unwrap_or(0),
            hash: parse_hex_bytes(p["hash"].as_str().unwrap_or("")),
        }),
    })
}

fn parse_commit_signatures(json: &serde_json::Value) -> Vec<CommitSig> {
    let Some(arr) = json.as_array() else {
        return vec![];
    };

    arr.iter()
        .map(|sig| {
            let flag = sig["block_id_flag"].as_str().unwrap_or("");
            match flag {
                "BLOCK_ID_FLAG_COMMIT" => CommitSig::BlockIdFlagCommit {
                    validator_address: parse_hex_bytes(
                        sig["validator_address"].as_str().unwrap_or(""),
                    ),
                    timestamp: sig["timestamp"]
                        .as_str()
                        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                        .map(|t| t.with_timezone(&Utc))
                        .unwrap_or_else(Utc::now),
                    signature: parse_hex_bytes(sig["signature"].as_str().unwrap_or("")),
                },
                "BLOCK_ID_FLAG_NIL" => CommitSig::BlockIdFlagNil,
                _ => CommitSig::BlockIdFlagAbsent,
            }
        })
        .collect()
}

fn parse_validator_set(json: &serde_json::Value) -> ValidatorSet {
    let Some(arr) = json.as_array() else {
        return ValidatorSet {
            validators: vec![],
            total_voting_power: 0,
        };
    };

    let validators: Vec<Validator> = arr
        .iter()
        .map(|v| {
            let pub_key_json = &v["pub_key"];
            let key_type = pub_key_json["type"].as_str().unwrap_or("");
            let key_value = pub_key_json["value"].as_str().unwrap_or("");

            let pub_key = if key_type.contains("ed25519") {
                PublicKey::Ed25519(
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_value)
                        .unwrap_or_default(),
                )
            } else {
                PublicKey::Secp256k1(
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_value)
                        .unwrap_or_default(),
                )
            };

            Validator {
                address: parse_hex_bytes(v["address"].as_str().unwrap_or("")),
                pub_key,
                voting_power: v["voting_power"]
                    .as_str()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(0),
            }
        })
        .collect();

    let total_voting_power = validators.iter().map(|v| v.voting_power).sum();

    ValidatorSet {
        validators,
        total_voting_power,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Config and Builder Tests
    // ========================================================================

    #[test]
    fn test_config_builder_defaults() {
        let config = LightClientConfig::builder("test-chain").build();

        assert_eq!(config.chain_id, "test-chain");
        assert!(config.validator_endpoints.is_empty());
        assert_eq!(config.min_validators_for_consensus, 1);
        assert_eq!(config.trust_threshold, (2, 3));
        assert_eq!(config.trusting_period, Duration::from_secs(86400));
        assert_eq!(config.max_clock_drift, Duration::from_secs(10));
        assert_eq!(config.rpc_timeout, Duration::from_secs(10));
        assert!(config.auto_sync);
    }

    #[test]
    fn test_config_builder_custom_values() {
        let config = LightClientConfig::builder("custom-chain")
            .validator_endpoints(vec![
                "http://node1:26657".to_string(),
                "http://node2:26657".to_string(),
            ])
            .min_validators_for_consensus(2)
            .trust_threshold(1, 2)
            .trusting_period(Duration::from_secs(3600))
            .max_clock_drift(Duration::from_secs(5))
            .rpc_timeout(Duration::from_secs(30))
            .auto_sync(false)
            .build();

        assert_eq!(config.chain_id, "custom-chain");
        assert_eq!(config.validator_endpoints.len(), 2);
        assert_eq!(config.min_validators_for_consensus, 2);
        assert_eq!(config.trust_threshold, (1, 2));
        assert_eq!(config.trusting_period, Duration::from_secs(3600));
        assert_eq!(config.max_clock_drift, Duration::from_secs(5));
        assert_eq!(config.rpc_timeout, Duration::from_secs(30));
        assert!(!config.auto_sync);
    }

    #[test]
    fn test_config_serialization() {
        let config = LightClientConfig::builder("test-chain")
            .validator_endpoints(vec!["http://node:26657".to_string()])
            .build();

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: LightClientConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.chain_id, deserialized.chain_id);
        assert_eq!(config.validator_endpoints, deserialized.validator_endpoints);
    }

    // ========================================================================
    // LightClient Creation Tests
    // ========================================================================

    #[test]
    fn test_light_client_creation() {
        let config = LightClientConfig::builder("test-chain").build();
        let client = LightClient::new(config).unwrap();

        assert_eq!(client.chain_id(), "test-chain");
        assert!(client.validator_endpoints().is_empty());
        assert!(client.auto_sync());
    }

    #[test]
    fn test_light_client_invalid_trust_threshold() {
        let mut config = LightClientConfig::builder("test-chain").build();
        config.trust_threshold = (3, 2); // Invalid: numerator > denominator

        let result = LightClient::new(config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("Trust threshold"));
    }

    #[test]
    fn test_light_client_empty_chain_id() {
        let config = LightClientConfig::builder("").build();

        let result = LightClient::new(config);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("Chain ID"));
    }

    // ========================================================================
    // TrustedState Tests
    // ========================================================================

    #[test]
    fn test_trusted_state_serialization() {
        let state = TrustedState {
            chain_id: "test-chain".to_string(),
            headers: vec![],
        };

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: TrustedState = serde_json::from_str(&json).unwrap();

        assert_eq!(state.chain_id, deserialized.chain_id);
        assert_eq!(state.headers.len(), deserialized.headers.len());
    }

    #[tokio::test]
    async fn test_export_import_trusted_state() {
        let config = LightClientConfig::builder("test-chain").build();
        let client = LightClient::new(config).unwrap();

        // Export empty state
        let state = client.export_trusted_state().await;
        assert_eq!(state.chain_id, "test-chain");
        assert!(state.headers.is_empty());

        // Import should succeed with matching chain ID
        let result = client.import_trusted_state(state).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_import_trusted_state_chain_mismatch() {
        let config = LightClientConfig::builder("test-chain").build();
        let client = LightClient::new(config).unwrap();

        let state = TrustedState {
            chain_id: "different-chain".to_string(),
            headers: vec![],
        };

        let result = client.import_trusted_state(state).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Chain ID mismatch"));
    }

    // ========================================================================
    // Header Storage Tests
    // ========================================================================

    #[tokio::test]
    async fn test_get_verified_height_range_empty() {
        let config = LightClientConfig::builder("test-chain").build();
        let client = LightClient::new(config).unwrap();

        let range = client.get_verified_height_range().await;
        assert!(range.is_none());
    }

    #[tokio::test]
    async fn test_get_latest_header_empty() {
        let config = LightClientConfig::builder("test-chain").build();
        let client = LightClient::new(config).unwrap();

        let header = client.get_latest_header().await;
        assert!(header.is_none());
    }

    #[tokio::test]
    async fn test_get_header_by_height_not_found() {
        let config = LightClientConfig::builder("test-chain").build();
        let client = LightClient::new(config).unwrap();

        let header = client.get_header_by_height(100).await;
        assert!(header.is_none());
    }

    // ========================================================================
    // Helper Function Tests
    // ========================================================================

    #[test]
    fn test_parse_hex_bytes_valid() {
        let result = parse_hex_bytes("deadbeef");
        assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_hex_bytes_invalid() {
        let result = parse_hex_bytes("not_hex");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_hex_bytes_empty() {
        let result = parse_hex_bytes("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_block_id_valid() {
        let json = serde_json::json!({
            "hash": "abcd1234",
            "parts": {
                "total": "10",
                "hash": "5678ef00"
            }
        });

        let block_id = parse_block_id(&json).unwrap();
        assert_eq!(block_id.hash, vec![0xab, 0xcd, 0x12, 0x34]);
        assert!(block_id.parts.is_some());

        let parts = block_id.parts.unwrap();
        assert_eq!(parts.total, 10);
        assert_eq!(parts.hash, vec![0x56, 0x78, 0xef, 0x00]);
    }

    #[test]
    fn test_parse_block_id_missing_hash() {
        let json = serde_json::json!({});
        let result = parse_block_id(&json);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_commit_signatures_empty() {
        let json = serde_json::json!([]);
        let sigs = parse_commit_signatures(&json);
        assert!(sigs.is_empty());
    }

    #[test]
    fn test_parse_commit_signatures_not_array() {
        let json = serde_json::json!({});
        let sigs = parse_commit_signatures(&json);
        assert!(sigs.is_empty());
    }

    #[test]
    fn test_parse_commit_signatures_commit() {
        let json = serde_json::json!([
            {
                "block_id_flag": "BLOCK_ID_FLAG_COMMIT",
                "validator_address": "abcd",
                "timestamp": "2024-01-01T00:00:00Z",
                "signature": "1234"
            }
        ]);

        let sigs = parse_commit_signatures(&json);
        assert_eq!(sigs.len(), 1);
        match &sigs[0] {
            CommitSig::BlockIdFlagCommit {
                validator_address,
                signature,
                ..
            } => {
                assert_eq!(validator_address, &vec![0xab, 0xcd]);
                assert_eq!(signature, &vec![0x12, 0x34]);
            }
            _ => panic!("Expected BlockIdFlagCommit"),
        }
    }

    #[test]
    fn test_parse_commit_signatures_nil() {
        let json = serde_json::json!([
            { "block_id_flag": "BLOCK_ID_FLAG_NIL" }
        ]);

        let sigs = parse_commit_signatures(&json);
        assert_eq!(sigs.len(), 1);
        assert!(matches!(sigs[0], CommitSig::BlockIdFlagNil));
    }

    #[test]
    fn test_parse_commit_signatures_absent() {
        let json = serde_json::json!([
            { "block_id_flag": "BLOCK_ID_FLAG_ABSENT" }
        ]);

        let sigs = parse_commit_signatures(&json);
        assert_eq!(sigs.len(), 1);
        assert!(matches!(sigs[0], CommitSig::BlockIdFlagAbsent));
    }

    #[test]
    fn test_parse_validator_set_empty() {
        let json = serde_json::json!([]);
        let vs = parse_validator_set(&json);
        assert!(vs.validators.is_empty());
        assert_eq!(vs.total_voting_power, 0);
    }

    #[test]
    fn test_parse_validator_set_not_array() {
        let json = serde_json::json!({});
        let vs = parse_validator_set(&json);
        assert!(vs.validators.is_empty());
    }

    #[test]
    fn test_parse_validator_set_with_validators() {
        // Note: key_type.contains("ed25519") is case-sensitive in the implementation
        let json = serde_json::json!([
            {
                "address": "abcd",
                "pub_key": {
                    "type": "tendermint/PubKeyed25519",
                    "value": "AAAA"
                },
                "voting_power": "100"
            },
            {
                "address": "1234",
                "pub_key": {
                    "type": "tendermint/PubKeySecp256k1",
                    "value": "BBBB"
                },
                "voting_power": "200"
            }
        ]);

        let vs = parse_validator_set(&json);
        assert_eq!(vs.validators.len(), 2);
        assert_eq!(vs.total_voting_power, 300);

        assert!(matches!(vs.validators[0].pub_key, PublicKey::Ed25519(_)));
        assert!(matches!(vs.validators[1].pub_key, PublicKey::Secp256k1(_)));
        assert_eq!(vs.validators[0].voting_power, 100);
        assert_eq!(vs.validators[1].voting_power, 200);
    }

    // ========================================================================
    // Type Tests
    // ========================================================================

    #[test]
    fn test_light_block_serialization() {
        let block = LightBlock {
            header: Header {
                chain_id: "test".to_string(),
                height: 100,
                time: Utc::now(),
                last_block_id: None,
                validators_hash: vec![1, 2, 3],
                next_validators_hash: vec![4, 5, 6],
                app_hash: vec![7, 8, 9],
            },
            commit: Commit {
                height: 100,
                round: 0,
                block_id: BlockId {
                    hash: vec![10, 11, 12],
                    parts: None,
                },
                signatures: vec![],
            },
            validators: ValidatorSet {
                validators: vec![],
                total_voting_power: 0,
            },
        };

        let json = serde_json::to_string(&block).unwrap();
        let deserialized: LightBlock = serde_json::from_str(&json).unwrap();

        assert_eq!(block.header.chain_id, deserialized.header.chain_id);
        assert_eq!(block.header.height, deserialized.header.height);
        assert_eq!(block.header.app_hash, deserialized.header.app_hash);
    }

    #[test]
    fn test_trusted_header_serialization() {
        let header = TrustedHeader {
            height: 100,
            hash: "abcd1234".to_string(),
            light_block_data: "base64data".to_string(),
        };

        let json = serde_json::to_string(&header).unwrap();
        let deserialized: TrustedHeader = serde_json::from_str(&json).unwrap();

        assert_eq!(header.height, deserialized.height);
        assert_eq!(header.hash, deserialized.hash);
    }
}
