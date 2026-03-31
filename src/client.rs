//! Main client for interacting with Willow

use crate::auth::{detect_algorithm_from_did, sign_challenge};
use crate::consensus::ConsensusClient;
use crate::data::DataOperations;
use crate::errors::{Result, WillowError};
use crate::indexing::IndexingOperations;
#[cfg(not(feature = "no-light-client"))]
use crate::light_client::{LightClient, LightClientConfig};
use crate::registration::RegistrationOperations;
use crate::token::TokenOperations;
use crate::types::{ApiResponse, HealthStatus, SignatureAlgorithm};
use crate::utils::{parse_api_url, RetryConfig};
use crate::validators::ValidatorOperations;
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::{Arc, RwLock};
use std::time::Duration;
#[cfg(not(feature = "no-light-client"))]
use tokio::sync::OnceCell;
use url::Url;

/// Identity for per-request signing
#[derive(Clone, Debug)]
struct ClientIdentity {
    did: String,
    private_key_hex: String,
    public_key_id: String,
    algorithm: SignatureAlgorithm,
}

/// Main client for interacting with Willow
#[derive(Clone)]
pub struct WillowClient {
    http_client: Client,
    base_url: Url,
    identity: Arc<RwLock<Option<ClientIdentity>>>,
    retry_config: RetryConfig,
    #[cfg(not(feature = "no-light-client"))]
    light_client: Option<Arc<LightClient>>,
    /// Lazily initialized light client for auto-initialization with trust-on-first-use
    #[cfg(not(feature = "no-light-client"))]
    light_client_once: Arc<OnceCell<Arc<LightClient>>>,
    /// Consensus client for submitting transactions to CometBFT
    consensus_client: Option<Arc<ConsensusClient>>,
}

impl WillowClient {
    /// Create a new Willow client
    pub async fn new(api_url: &str) -> Result<Self> {
        Self::builder().api_url(api_url).build().await
    }

    /// Create a client builder
    pub fn builder() -> WillowClientBuilder {
        WillowClientBuilder::default()
    }

    /// Set identity for per-request signing.
    ///
    /// All subsequent requests will include signature headers automatically.
    pub fn set_identity(&self, did: &str, private_key_hex: &str, public_key_id: &str) {
        let algorithm = detect_algorithm_from_did(did);
        let mut identity_lock = self.identity.write().unwrap();
        *identity_lock = Some(ClientIdentity {
            did: did.to_string(),
            private_key_hex: private_key_hex.to_string(),
            public_key_id: public_key_id.to_string(),
            algorithm,
        });
    }

    /// Check if an identity is set for signing.
    pub fn has_identity(&self) -> bool {
        self.identity.read().unwrap().is_some()
    }

    /// Get the current DID, if identity is set.
    pub fn get_did(&self) -> Option<String> {
        self.identity.read().unwrap().as_ref().map(|i| i.did.clone())
    }

    /// Clear the current identity.
    pub fn clear_identity(&self) {
        let mut identity_lock = self.identity.write().unwrap();
        *identity_lock = None;
    }

    /// Require that an identity is set, returning an error if not.
    pub fn require_auth(&self) -> Result<()> {
        if !self.has_identity() {
            return Err(WillowError::NotAuthenticated);
        }
        Ok(())
    }

    /// Sign a request and return the headers map.
    fn sign_request(&self, method: &str, path: &str) -> Option<Vec<(String, String)>> {
        let identity_lock = self.identity.read().unwrap();
        let identity = identity_lock.as_ref()?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let message = format!("{}:{}:{}", method, path, timestamp);

        let signature = sign_challenge(&message, &identity.private_key_hex, identity.algorithm).ok()?;

        Some(vec![
            ("X-DID".to_string(), identity.did.clone()),
            ("X-Public-Key-ID".to_string(), identity.public_key_id.clone()),
            ("X-Signature".to_string(), signature),
            ("X-Timestamp".to_string(), timestamp),
        ])
    }

    /// Get data operations
    pub fn data(&self) -> DataOperations {
        DataOperations::new(self.clone())
    }

    /// Get file storage operations
    pub fn files(&self) -> crate::files::FileOperations {
        crate::files::FileOperations::new(self.clone())
    }

    /// Get privacy operations for private subgroves
    pub fn privacy(&self) -> crate::privacy::PrivacyOperations {
        crate::privacy::PrivacyOperations::new(self.clone())
    }

    /// Get the light client if configured.
    ///
    /// Returns `None` if `no-light-client` feature is enabled.
    #[cfg(not(feature = "no-light-client"))]
    pub fn light_client(&self) -> Option<Arc<LightClient>> {
        self.light_client.clone()
    }

    /// Get or create a light client with trust-on-first-use initialization.
    ///
    /// This method returns an existing light client if configured, or automatically
    /// creates and initializes one using trust-on-first-use. The initialization
    /// is thread-safe and happens only once.
    ///
    /// Important: TODO: When mainnet/testnet launches, replace trust-on-first-use
    /// with hardcoded checkpoint headers for true trustless initialization.
    /// Trust-on-first-use is secure for subsequent operations but trusts the
    /// initial block from the connected validators.
    ///
    /// Returns `None` if `no-light-client` feature is enabled.
    #[cfg(not(feature = "no-light-client"))]
    pub async fn get_or_create_light_client(&self) -> Result<Arc<LightClient>> {
        // Return existing explicitly configured light client if available
        if let Some(lc) = &self.light_client {
            return Ok(lc.clone());
        }

        // Use OnceCell to ensure only one initialization happens
        let lc = self
            .light_client_once
            .get_or_try_init(|| async {
                // TODO: When mainnet/testnet launches, use hardcoded checkpoint headers
                // instead of trust-on-first-use for true trustless initialization from genesis.

                // Derive CometBFT RPC endpoint from API URL (typically :3031 -> :26657)
                let rpc_endpoint = self.base_url.to_string().replace(":3031", ":26657");

                let config = LightClientConfig::builder("willow-chain")
                    .validator_endpoints(vec![rpc_endpoint])
                    .trust_threshold(2, 3)
                    .trusting_period(Duration::from_secs(86400)) // 24 hours
                    .max_clock_drift(Duration::from_secs(30))
                    .rpc_timeout(Duration::from_secs(30))
                    .auto_sync(false)
                    .build();

                let lc = Arc::new(LightClient::new(config)?);
                lc.initialize_with_trust_on_first_use().await?;

                Ok::<Arc<LightClient>, WillowError>(lc)
            })
            .await?;

        Ok(lc.clone())
    }

    /// Get registration operations
    pub fn registration(&self) -> RegistrationOperations {
        RegistrationOperations::new(self.clone())
    }

    /// Get token operations (balances, fees)
    pub fn token(&self) -> TokenOperations {
        TokenOperations::new(self.clone())
    }

    /// Get validator operations
    pub fn validators(&self) -> ValidatorOperations {
        ValidatorOperations::new(self.clone())
    }

    /// Get indexing operations (GraphQL, subgroves)
    pub fn indexing(&self) -> IndexingOperations {
        IndexingOperations::new(self.clone())
    }

    /// Get consensus operations for submitting transactions.
    ///
    /// Returns the consensus client if a consensus URL was configured.
    /// Use this for operations that require blockchain consensus:
    /// - DID registration
    /// - App registration
    /// - Subgrove registration
    /// - Token transfers
    /// - Data storage through consensus
    ///
    /// # Panics
    /// Panics if no consensus URL was configured. Use `consensus_opt()` for a non-panicking version.
    ///
    /// # Example
    /// ```rust,no_run
    /// use willow_sdk::WillowClient;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = WillowClient::builder()
    ///         .api_url("http://localhost:3031")
    ///         .consensus_url("http://localhost:26657")
    ///         .build()
    ///         .await?;
    ///
    ///     // Submit transactions through consensus
    ///     let consensus = client.consensus();
    ///     // consensus.register_did(...).await?;
    ///     Ok(())
    /// }
    /// ```
    pub fn consensus(&self) -> &ConsensusClient {
        self.consensus_client
            .as_ref()
            .expect("Consensus client not configured. Use WillowClientBuilder::consensus_url() to configure.")
    }

    /// Get consensus operations if configured, or None.
    ///
    /// Non-panicking version of `consensus()`.
    pub fn consensus_opt(&self) -> Option<&ConsensusClient> {
        self.consensus_client.as_ref().map(|c| c.as_ref())
    }

    /// Check the health of the Willow node
    pub async fn health(&self) -> Result<HealthStatus> {
        let response: ApiResponse<HealthStatus> =
            self.request("GET", "/health", None::<&()>, false).await?;

        response
            .data
            .ok_or_else(|| WillowError::Custom("No health data in response".to_string()))
    }

    /// Get the verified root hash from the blockchain consensus.
    ///
    /// This method returns the root hash that has been verified through blockchain consensus,
    /// providing stronger security guarantees than the local root hash. This is the recommended
    /// method for applications that need cryptographic proof of the current state.
    ///
    /// # Returns
    /// The current verified root hash as a hex string
    ///
    /// # Errors
    /// Returns an error if the request fails or if no root hash is available
    pub async fn get_root_hash(&self) -> Result<String> {
        let response: ApiResponse<serde_json::Value> = self
            .request("GET", "/state/root-hash/verified", None::<&()>, false)
            .await?;

        response
            .data
            .and_then(|data| {
                data.get("root_hash")
                    .and_then(|h| h.as_str())
                    .map(String::from)
            })
            .ok_or_else(|| WillowError::Custom("No root hash in response".to_string()))
    }

    /// Get the local root hash from the node's current state.
    ///
    /// This method returns the root hash from the node's local state, which may not yet be
    /// verified through consensus. This is useful for debugging or when you need the absolute
    /// latest state, but it provides weaker security guarantees than `get_root_hash()`.
    ///
    /// For most applications, use `get_root_hash()` instead for verified blockchain state.
    ///
    /// # Returns
    /// The current local root hash as a hex string
    ///
    /// # Errors
    /// Returns an error if the request fails or if no root hash is available
    pub async fn get_root_hash_local(&self) -> Result<String> {
        let response: ApiResponse<serde_json::Value> = self
            .request("GET", "/state/root-hash", None::<&()>, false)
            .await?;

        response
            .data
            .and_then(|data| {
                data.get("root_hash")
                    .and_then(|h| h.as_str())
                    .map(String::from)
            })
            .ok_or_else(|| WillowError::Custom("No root hash in response".to_string()))
    }

    /// Make an authenticated request
    pub async fn request<T, B>(
        &self,
        method: &str,
        path: &str,
        body: Option<&B>,
        authenticated: bool,
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.request_with_retry(method, path, body, authenticated)
            .await
    }

    /// Make a request with retry logic
    async fn request_with_retry<T, B>(
        &self,
        method: &str,
        path: &str,
        body: Option<&B>,
        authenticated: bool,
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let mut last_error = None;

        for attempt in 0..self.retry_config.max_attempts {
            match self
                .make_request::<T, B>(method, path, body, authenticated)
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.retry_config.max_attempts - 1 {
                        let delay = crate::utils::calculate_backoff(attempt, &self.retry_config);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }

    /// Make a single request
    async fn make_request<T, B>(
        &self,
        method: &str,
        path: &str,
        body: Option<&B>,
        authenticated: bool,
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self.base_url.join(path.trim_start_matches('/'))?;
        let mut request = self.http_client.request(
            method
                .parse()
                .map_err(|_| WillowError::Config(format!("Invalid HTTP method: {}", method)))?,
            url.clone(),
        );

        // Add signature headers if identity is set
        if let Some(headers) = self.sign_request(method, path) {
            for (key, value) in headers {
                request = request.header(&key, &value);
            }
        } else if authenticated {
            return Err(WillowError::NotAuthenticated);
        }

        // Add body if provided
        if let Some(body_data) = body {
            request = request.json(body_data);
        }

        // Send request
        let response = request.send().await?;
        let status = response.status();

        // Parse response
        let response_text = response.text().await?;

        if status.is_success() {
            serde_json::from_str(&response_text).map_err(|e| WillowError::Serialization(e))
        } else {
            // Try to parse error response
            if let Ok(api_response) =
                serde_json::from_str::<ApiResponse<serde_json::Value>>(&response_text)
            {
                if let Some(error_msg) = api_response.error {
                    match status {
                        StatusCode::NOT_FOUND => Err(WillowError::NotFound(error_msg)),
                        StatusCode::UNAUTHORIZED => Err(WillowError::Authentication(error_msg)),
                        StatusCode::FORBIDDEN => Err(WillowError::PermissionDenied(error_msg)),
                        _ => Err(WillowError::Http {
                            status: status.as_u16(),
                            message: error_msg,
                        }),
                    }
                } else {
                    Err(WillowError::Http {
                        status: status.as_u16(),
                        message: "Unknown error".to_string(),
                    })
                }
            } else {
                Err(WillowError::Http {
                    status: status.as_u16(),
                    message: response_text,
                })
            }
        }
    }
}

/// Builder for WillowClient
pub struct WillowClientBuilder {
    api_url: Option<String>,
    consensus_url: Option<String>,
    timeout: Duration,
    retry_config: RetryConfig,
    #[cfg(not(feature = "no-light-client"))]
    light_client_config: Option<LightClientConfig>,
}

impl Default for WillowClientBuilder {
    fn default() -> Self {
        Self {
            api_url: None,
            consensus_url: None,
            timeout: Duration::from_secs(30),
            retry_config: RetryConfig::default(),
            #[cfg(not(feature = "no-light-client"))]
            light_client_config: None,
        }
    }
}

impl WillowClientBuilder {
    /// Set the API URL
    pub fn api_url(mut self, url: &str) -> Self {
        self.api_url = Some(url.to_string());
        self
    }

    /// Set the CometBFT consensus RPC URL.
    ///
    /// Required for consensus operations like DID registration, app registration,
    /// token transfers, and data storage through consensus.
    ///
    /// # Example
    /// ```rust,no_run
    /// use willow_sdk::WillowClient;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = WillowClient::builder()
    ///         .api_url("http://localhost:3031")
    ///         .consensus_url("http://localhost:26657")
    ///         .build()
    ///         .await?;
    ///     Ok(())
    /// }
    /// ```
    pub fn consensus_url(mut self, url: &str) -> Self {
        self.consensus_url = Some(url.to_string());
        self
    }

    /// Set the request timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the retry configuration
    pub fn retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Set the light client configuration for trustless verification.
    ///
    /// Not available with `no-light-client` feature.
    #[cfg(not(feature = "no-light-client"))]
    pub fn light_client_config(mut self, config: LightClientConfig) -> Self {
        self.light_client_config = Some(config);
        self
    }

    /// Set the light client configuration from a file.
    ///
    /// Not available with `no-light-client` feature.
    #[cfg(not(feature = "no-light-client"))]
    pub fn light_client_config_file(mut self, path: &str) -> Result<Self> {
        let config_str = std::fs::read_to_string(path).map_err(|e| {
            WillowError::Config(format!("Failed to read light client config: {}", e))
        })?;
        let config: LightClientConfig = serde_json::from_str(&config_str)
            .map_err(|e| WillowError::Config(format!("Invalid light client config: {}", e)))?;
        self.light_client_config = Some(config);
        Ok(self)
    }

    /// Build the client
    pub async fn build(self) -> Result<WillowClient> {
        let api_url = self
            .api_url
            .unwrap_or_else(|| "http://localhost:3031".to_string());

        let base_url = parse_api_url(&api_url)?;

        let http_client = Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| WillowError::Config(format!("Failed to build HTTP client: {}", e)))?;

        // Create light client if configured
        #[cfg(not(feature = "no-light-client"))]
        let light_client = if let Some(config) = self.light_client_config {
            Some(Arc::new(LightClient::new(config)?))
        } else {
            None
        };

        // Create consensus client if configured
        let consensus_client = self
            .consensus_url
            .map(|url| Arc::new(ConsensusClient::new(&url)));

        Ok(WillowClient {
            http_client,
            base_url,
            identity: Arc::new(RwLock::new(None)),
            retry_config: self.retry_config,
            #[cfg(not(feature = "no-light-client"))]
            light_client,
            #[cfg(not(feature = "no-light-client"))]
            light_client_once: Arc::new(OnceCell::new()),
            consensus_client,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Client Creation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_client_new_default_url() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        assert!(!client.has_identity());
        assert!(client.get_did().is_none());
    }

    #[tokio::test]
    async fn test_client_builder_default() {
        let client = WillowClient::builder()
            .api_url("http://localhost:3031")
            .build()
            .await
            .unwrap();

        assert!(!client.has_identity());
    }

    #[tokio::test]
    async fn test_client_builder_with_timeout() {
        let client = WillowClient::builder()
            .api_url("http://localhost:3031")
            .timeout(Duration::from_secs(60))
            .build()
            .await
            .unwrap();

        assert!(!client.has_identity());
    }

    #[tokio::test]
    async fn test_client_builder_with_retry_config() {
        let retry_config = RetryConfig {
            max_attempts: 5,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            exponential_base: 2.0,
        };

        let client = WillowClient::builder()
            .api_url("http://localhost:3031")
            .retry_config(retry_config)
            .build()
            .await
            .unwrap();

        assert!(!client.has_identity());
    }

    #[tokio::test]
    async fn test_client_invalid_url() {
        // Empty string should be invalid
        let result = WillowClient::new("").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_client_url_normalization() {
        // URL without protocol should work (gets http:// prefix)
        let client = WillowClient::new("localhost:3031").await.unwrap();
        assert!(!client.has_identity());
    }

    // ========================================================================
    // Identity Tests
    // ========================================================================

    #[tokio::test]
    async fn test_no_identity() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();

        assert!(!client.has_identity());
        assert!(client.get_did().is_none());
    }

    #[tokio::test]
    async fn test_set_and_clear_identity() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();

        client.set_identity(
            "did:willow:Ed25519:abc123",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "did:willow:Ed25519:abc123#key-1",
        );
        assert!(client.has_identity());
        assert_eq!(client.get_did(), Some("did:willow:Ed25519:abc123".to_string()));

        client.clear_identity();
        assert!(!client.has_identity());
        assert!(client.get_did().is_none());
    }

    #[tokio::test]
    async fn test_require_auth_without_identity() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        assert!(client.require_auth().is_err());
    }

    #[tokio::test]
    async fn test_require_auth_with_identity() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        client.set_identity(
            "did:willow:Ed25519:abc123",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "did:willow:Ed25519:abc123#key-1",
        );
        assert!(client.require_auth().is_ok());
    }

    // ========================================================================
    // Operations Access Tests
    // ========================================================================

    #[tokio::test]
    async fn test_data_operations_access() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        let _data_ops = client.data();
        // Should not panic - just verifies access works
    }

    #[tokio::test]
    async fn test_registration_operations_access() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        let _reg_ops = client.registration();
    }

    #[tokio::test]
    async fn test_token_operations_access() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        let _token_ops = client.token();
    }

    #[tokio::test]
    async fn test_validator_operations_access() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        let _val_ops = client.validators();
    }

    #[tokio::test]
    async fn test_indexing_operations_access() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        let _idx_ops = client.indexing();
    }

    // ========================================================================
    // Light Client Tests (when feature enabled)
    // ========================================================================

    #[cfg(not(feature = "no-light-client"))]
    #[tokio::test]
    async fn test_light_client_not_configured() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        assert!(client.light_client().is_none());
    }

    #[cfg(not(feature = "no-light-client"))]
    #[tokio::test]
    async fn test_light_client_configured() {
        use crate::light_client::LightClientConfig;

        let lc_config = LightClientConfig::builder("test-chain").build();

        let client = WillowClient::builder()
            .api_url("http://localhost:3031")
            .light_client_config(lc_config)
            .build()
            .await
            .unwrap();

        assert!(client.light_client().is_some());
    }

    // ========================================================================
    // Builder Default Tests
    // ========================================================================

    #[test]
    fn test_builder_default_values() {
        let builder = WillowClientBuilder::default();
        assert!(builder.api_url.is_none());
        assert_eq!(builder.timeout, Duration::from_secs(30));
    }
}
