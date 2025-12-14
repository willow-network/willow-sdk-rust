//! Main client for interacting with Willow

use crate::auth::{detect_algorithm_from_did, sign_challenge};
use crate::data::DataOperations;
use crate::errors::{WillowError, Result};
use crate::indexing::IndexingOperations;
#[cfg(not(feature = "no-light-client"))]
use crate::light_client::{LightClient, LightClientConfig};
use crate::registration::RegistrationOperations;
use crate::token::TokenOperations;
use crate::types::{
    ApiResponse, AuthenticationChallenge, AuthenticationResponse, DidDocument, HealthStatus,
    Session,
};
use crate::utils::{parse_api_url, RetryConfig};
use crate::validators::ValidatorOperations;
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(not(feature = "no-light-client"))]
use tokio::sync::OnceCell;
use url::Url;

/// Main client for interacting with Willow
#[derive(Clone)]
pub struct WillowClient {
    http_client: Client,
    base_url: Url,
    session: Arc<Mutex<Option<Session>>>,
    retry_config: RetryConfig,
    #[cfg(not(feature = "no-light-client"))]
    light_client: Option<Arc<LightClient>>,
    /// Lazily initialized light client for auto-initialization with trust-on-first-use
    #[cfg(not(feature = "no-light-client"))]
    light_client_once: Arc<OnceCell<Arc<LightClient>>>,
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

    /// Register a DID document
    pub async fn register_did(&self, did_document: &DidDocument) -> Result<DidDocument> {
        let response: ApiResponse<DidDocument> = self
            .request_with_retry("POST", "/did", Some(did_document), false)
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::Custom("No data in response".to_string()))
    }

    /// Authenticate with DID and private key
    pub async fn authenticate(
        &self,
        did: &str,
        private_key_hex: &str,
        public_key_id: &str,
    ) -> Result<Session> {
        // Get challenge
        let challenge_response: ApiResponse<AuthenticationChallenge> = self
            .request_with_retry(
                "GET",
                &format!("/auth/challenge/{}", did),
                None::<&()>,
                false,
            )
            .await?;

        let challenge = challenge_response
            .data
            .ok_or_else(|| WillowError::Authentication("No challenge received".to_string()))?;

        // Sign challenge - must match server's expected format
        let message = format!(
            "DID Authentication\nChallenge: {}\nNonce: {}\nDID: {}\nExpires: {}",
            challenge.challenge,
            challenge.nonce.as_ref().unwrap_or(&"".to_string()),
            challenge.did.as_ref().unwrap_or(&did.to_string()),
            challenge.expires_at
        );
        let algorithm = detect_algorithm_from_did(did);
        let signature = sign_challenge(&message, private_key_hex, algorithm)?;

        // Create auth response
        let auth_response = AuthenticationResponse {
            did: did.to_string(),
            challenge: challenge.challenge.clone(),
            signature,
            public_key_id: public_key_id.to_string(),
        };

        // Verify authentication
        let body = serde_json::json!([challenge, auth_response]);
        let session_response: ApiResponse<Session> = self
            .request_with_retry("POST", "/auth/verify", Some(&body), false)
            .await?;

        let session = session_response
            .data
            .ok_or_else(|| WillowError::Authentication("No session received".to_string()))?;

        // Store session
        {
            let mut session_lock = self.session.lock().unwrap();
            *session_lock = Some(session.clone());
        }

        Ok(session)
    }

    /// Check if authenticated
    pub fn is_authenticated(&self) -> bool {
        let session_lock = self.session.lock().unwrap();
        if let Some(session) = &*session_lock {
            !session.is_expired()
        } else {
            false
        }
    }

    /// Get current session
    pub fn get_session(&self) -> Option<Session> {
        let session_lock = self.session.lock().unwrap();
        session_lock.clone()
    }

    /// Clear session (logout)
    pub fn clear_session(&self) {
        let mut session_lock = self.session.lock().unwrap();
        *session_lock = None;
    }

    /// Get data operations
    pub fn data(&self) -> DataOperations {
        DataOperations::new(self.clone())
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
        let lc = self.light_client_once.get_or_try_init(|| async {
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
        }).await?;

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

    /// Get indexing operations (GraphQL, subgraphs)
    pub fn indexing(&self) -> IndexingOperations {
        IndexingOperations::new(self.clone())
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

        // Add authentication if required
        if authenticated {
            let session = self.get_session().ok_or(WillowError::NotAuthenticated)?;

            if session.is_expired() {
                return Err(WillowError::SessionExpired);
            }

            request = request.query(&[("did", &session.did)]).query(&[(
                "session",
                &session.session_id.as_ref().unwrap_or(&session.did),
            )]);
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
    timeout: Duration,
    retry_config: RetryConfig,
    #[cfg(not(feature = "no-light-client"))]
    light_client_config: Option<LightClientConfig>,
}

impl Default for WillowClientBuilder {
    fn default() -> Self {
        Self {
            api_url: None,
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

        Ok(WillowClient {
            http_client,
            base_url,
            session: Arc::new(Mutex::new(None)),
            retry_config: self.retry_config,
            #[cfg(not(feature = "no-light-client"))]
            light_client,
            #[cfg(not(feature = "no-light-client"))]
            light_client_once: Arc::new(OnceCell::new()),
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
        assert!(!client.is_authenticated());
        assert!(client.get_session().is_none());
    }

    #[tokio::test]
    async fn test_client_builder_default() {
        let client = WillowClient::builder()
            .api_url("http://localhost:3031")
            .build()
            .await
            .unwrap();

        assert!(!client.is_authenticated());
    }

    #[tokio::test]
    async fn test_client_builder_with_timeout() {
        let client = WillowClient::builder()
            .api_url("http://localhost:3031")
            .timeout(Duration::from_secs(60))
            .build()
            .await
            .unwrap();

        assert!(!client.is_authenticated());
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

        assert!(!client.is_authenticated());
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
        assert!(!client.is_authenticated());
    }

    // ========================================================================
    // Session Tests
    // ========================================================================

    #[tokio::test]
    async fn test_session_not_authenticated() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();

        assert!(!client.is_authenticated());
        assert!(client.get_session().is_none());
    }

    #[tokio::test]
    async fn test_clear_session() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();

        // Even if not authenticated, clear_session should work
        client.clear_session();
        assert!(client.get_session().is_none());
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
