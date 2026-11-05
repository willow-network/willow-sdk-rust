//! Main client for interacting with Willow

use crate::auth::{
    detect_algorithm_from_did, legacy_request_message, sign_request_message,
    sign_request_with_nonce,
};
use crate::consensus::ConsensusClient;
use crate::data::DataOperations;
use crate::errors::{Result, WillowError};
use crate::indexers::WillowIndexers;
use crate::indexing::IndexingOperations;
#[cfg(not(feature = "no-light-client"))]
use crate::light_client::{LightClient, LightClientConfig};
use crate::registration::RegistrationOperations;
use crate::token::TokenOperations;
use crate::types::{ApiResponse, DidInfo, HealthStatus, SignatureAlgorithm};
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

/// How long a request the SDK sends may take, unless the caller sets another timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// An HTTP client whose requests time out after `timeout`.
pub(crate) fn http_client_with_timeout(timeout: Duration) -> Client {
    Client::builder()
        .timeout(timeout)
        .build()
        .expect("an HTTP client with a timeout and default settings")
}

/// The CometBFT RPC of a local node, beside an API on a loopback host at port 3031: the same
/// URL at port 26657. `None` for any other API URL.
#[cfg(not(feature = "no-light-client"))]
fn local_consensus_rpc(api: &Url) -> Option<String> {
    let loopback = match api.host()? {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip == std::net::Ipv4Addr::LOCALHOST,
        url::Host::Ipv6(ip) => ip == std::net::Ipv6Addr::LOCALHOST,
    };
    if !loopback || api.port() != Some(3031) {
        return None;
    }
    let mut rpc = api.clone();
    rpc.set_port(Some(26657)).ok()?;
    rpc.set_path("");
    rpc.set_query(None);
    Some(rpc.as_str().trim_end_matches('/').to_string())
}

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
    pub(crate) http_client: Client,
    /// The timeout of `http_client`, for the clients the SDK makes for other servers.
    pub(crate) timeout: Duration,
    base_url: Url,
    /// Optional indexer URL for routing GraphQL/SQL queries to an indexer node.
    indexer_url: Option<Url>,
    /// Indexer discovery client. Normal callers use the source-routed query
    /// methods on `indexing()` / `data()` — this is surfaced for listing.
    indexers: WillowIndexers,
    identity: Arc<RwLock<Option<ClientIdentity>>>,
    retry_config: RetryConfig,
    #[cfg(not(feature = "no-light-client"))]
    light_client: Option<Arc<LightClient>>,
    /// Lazily initialized light client for auto-initialization with trust-on-first-use
    #[cfg(not(feature = "no-light-client"))]
    light_client_once: Arc<OnceCell<Arc<LightClient>>>,
    /// Consensus client for submitting transactions to CometBFT
    consensus_client: Option<Arc<ConsensusClient>>,
    /// Per-subgrove last-seen state root. Populated by `verifiable_rpc().query()`
    /// so the client can detect forks or stale state across calls on the
    /// same session (chain-from-last-seen). Stored on the client so the
    /// cache survives `VerifiableRpcOperations` going out of scope.
    pub(crate) state_root_cache: Arc<RwLock<std::collections::HashMap<String, SeenStateRoot>>>,
    /// Verification policy for verifiable RPC responses.
    pub(crate) verify_mode: Arc<RwLock<VerifyMode>>,
}

/// Policy for how strictly the client verifies a verifiable-RPC response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// Require both a valid GKR proof and a valid GroveDB proof. Default.
    /// `GKR_PROOF_FULL` proofs are verified end-to-end against
    /// compiled-circuit bytes embedded at build time.
    Strict,
    /// Require a GroveDB proof; accept responses without a full GKR
    /// check. Caller anchors `state_root` out-of-band (e.g. via the
    /// consensus light client).
    GroveDbOnly,
    /// Skip verification entirely. Debug/development only — never use in
    /// production.
    Disabled,
}

impl Default for VerifyMode {
    fn default() -> Self {
        VerifyMode::Strict
    }
}

/// Cached record of a state root we've observed for a subgrove.
///
/// The client uses this to detect two problems: (1) an indexer that
/// starts serving a *different* state root for an earlier block range
/// (fork / rewrite) and (2) responses that advance the state root
/// backwards (stale indexer serving an old checkpoint).
#[derive(Debug, Clone)]
pub struct SeenStateRoot {
    pub state_root: [u8; 32],
    pub block_range: (u64, u64),
    pub checkpoint_id: [u8; 32],
    pub observed_at_unix_secs: u64,
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
    ///
    /// The signing algorithm is inferred from `did` via
    /// [`detect_algorithm_from_did`](crate::auth::detect_algorithm_from_did),
    /// which defaults to Ed25519. Self-certifying `did:willow:z...` ids do **not**
    /// encode their algorithm in the string, so this convenience method assumes
    /// Ed25519 for them. A secp256k1 (Ethereum/wallet) identity backed by a
    /// self-certifying id **must** instead use
    /// [`set_identity_with_algorithm`](Self::set_identity_with_algorithm) or
    /// [`set_identity_from_did_info`](Self::set_identity_from_did_info); otherwise
    /// per-request auth would be signed with the wrong algorithm and rejected.
    pub fn set_identity(&self, did: &str, private_key_hex: &str, public_key_id: &str) {
        let algorithm = detect_algorithm_from_did(did);
        self.set_identity_with_algorithm(did, private_key_hex, public_key_id, algorithm);
    }

    /// Set identity for per-request signing with an explicit signing algorithm.
    ///
    /// Use this when the algorithm cannot be inferred from the DID string, which
    /// is always the case for self-certifying `did:willow:z...` ids. Pass the
    /// algorithm that matches `private_key_hex` (e.g.
    /// [`SignatureAlgorithm::Secp256k1`] for an Ethereum/wallet key) so that
    /// per-request auth is signed with the correct scheme.
    pub fn set_identity_with_algorithm(
        &self,
        did: &str,
        private_key_hex: &str,
        public_key_id: &str,
        algorithm: SignatureAlgorithm,
    ) {
        let mut identity_lock = self.identity.write().unwrap();
        *identity_lock = Some(ClientIdentity {
            did: did.to_string(),
            private_key_hex: private_key_hex.to_string(),
            public_key_id: public_key_id.to_string(),
            algorithm,
        });
    }

    /// Set identity for per-request signing directly from a [`DidInfo`].
    ///
    /// This is the recommended path: [`DidInfo`] already carries the correct
    /// [`SignatureAlgorithm`], so the signing algorithm is taken from it rather
    /// than guessed from the (self-certifying) DID string. Works correctly for
    /// both Ed25519 and secp256k1 identities produced by
    /// [`generate_did`](crate::auth::generate_did).
    pub fn set_identity_from_did_info(&self, did_info: &DidInfo) {
        self.set_identity_with_algorithm(
            &did_info.did,
            &did_info.private_key_hex(),
            &did_info.public_key_id,
            did_info.algorithm,
        );
    }

    /// Check if an identity is set for signing.
    pub fn has_identity(&self) -> bool {
        self.identity.read().unwrap().is_some()
    }

    /// Get the current DID, if identity is set.
    pub fn get_did(&self) -> Option<String> {
        self.identity
            .read()
            .unwrap()
            .as_ref()
            .map(|i| i.did.clone())
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

    /// Sign a request in the older `{METHOD}:{PATH}:{TIMESTAMP}` form and return the
    /// headers. PATH is the path alone: any query string is left out, as the server
    /// verifies it (see [`crate::auth::legacy_request_message`]). This form carries no
    /// read rights; reads of subgrove data use [`Self::sign_request_with_nonce`].
    pub(crate) fn sign_request(&self, method: &str, path: &str) -> Option<Vec<(String, String)>> {
        let identity_lock = self.identity.read().unwrap();
        let identity = identity_lock.as_ref()?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let message = legacy_request_message(method, path, &timestamp);

        let signature =
            sign_request_message(&message, &identity.private_key_hex, identity.algorithm).ok()?;

        Some(vec![
            ("X-DID".to_string(), identity.did.clone()),
            (
                "X-Public-Key-ID".to_string(),
                identity.public_key_id.clone(),
            ),
            ("X-Signature".to_string(), signature),
            ("X-Timestamp".to_string(), timestamp),
        ])
    }

    /// Sign a request to the API with a one-time nonce over its method, path and
    /// query, and body, when an identity is set. Only this form carries the DID's read
    /// rights. `body` must be the exact bytes sent; each call draws a fresh nonce, so
    /// sign every attempt anew.
    pub(crate) fn sign_request_with_nonce(
        &self,
        method: &str,
        url: &Url,
        body: &[u8],
    ) -> Result<Option<Vec<(String, String)>>> {
        let identity_lock = self.identity.read().unwrap();
        let Some(identity) = identity_lock.as_ref() else {
            return Ok(None);
        };
        sign_request_with_nonce(
            &identity.did,
            &identity.public_key_id,
            &identity.private_key_hex,
            identity.algorithm,
            method,
            &self.api_target(url),
            body,
        )
        .map(Some)
    }

    /// The path and query the API receives for `url`: what the request line carries,
    /// less any path the API base URL adds (a proxy mounted under a path strips it).
    pub(crate) fn api_target(&self, url: &Url) -> String {
        let mut target = url.path().to_string();
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }
        let base = self.base_url.path().trim_end_matches('/');
        if !base.is_empty() && target.starts_with(&format!("{base}/")) {
            target.drain(..base.len());
        }
        target
    }

    /// The configured indexer URL; indexer-only routes have no API fallback.
    pub(crate) fn require_indexer_url(&self) -> Result<&Url> {
        self.indexer_url.as_ref().ok_or_else(|| {
            WillowError::Config(
                "this route is served by indexers only: set indexer_url on the client builder"
                    .to_string(),
            )
        })
    }

    /// Whether GraphQL/SQL reads sent to [`Self::indexer_base_url`] go to the API.
    pub(crate) fn queries_go_to_api(&self) -> bool {
        self.indexer_url.is_none()
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
    /// The light client created here reads headers from the consensus node the caller
    /// configures: the consensus URL. Only for an API on a loopback host (`localhost`,
    /// `127.0.0.1`, `::1`) at port 3031, as a local node runs, does it read them from the same
    /// host at port 26657 without one. Any other API URL with no consensus URL is a
    /// configuration error: the root a read is checked against comes from a node the caller
    /// chose, not from the API that served the data.
    ///
    /// Verified reads check the proof against the app hash that consensus node reports, and the
    /// SDK trusts that node: it does not verify validator signatures over CometBFT's canonical
    /// vote bytes (see [`crate::light_client`]). Configure `light_client_config` with the
    /// endpoints you trust.
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
                let rpc_endpoint = match self.consensus_opt() {
                    Some(consensus) => consensus.rpc_url().trim_end_matches('/').to_string(),
                    None => local_consensus_rpc(&self.base_url).ok_or_else(|| {
                        WillowError::Config(
                            "a verified read checks its proof against the app hash a consensus \
                             node reports, and the SDK trusts that node: set consensus_url or \
                             light_client_config on the builder (only an API on a loopback host \
                             at port 3031 implies its local node at port 26657)"
                                .to_string(),
                        )
                    })?,
                };

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

    /// Returns the indexer base URL if configured, otherwise the validator API base URL.
    ///
    /// Used by indexing operations to route GraphQL/SQL queries to an indexer node
    /// when `indexer_url` is set on the client builder.
    pub fn indexer_base_url(&self) -> &Url {
        self.indexer_url.as_ref().unwrap_or(&self.base_url)
    }

    /// Returns the validator API base URL (unchanged regardless of indexer config).
    pub(crate) fn validator_base_url(&self) -> &Url {
        &self.base_url
    }

    /// Access the indexer discovery client.
    ///
    /// When the client was built without `indexer_url`, calls `GET /indexers`
    /// on the validator with a 30-second cache. When `indexer_url` was set
    /// explicitly, discovery is bypassed and a synthetic single-entry list
    /// is returned.
    pub fn indexers(&self) -> &WillowIndexers {
        &self.indexers
    }

    /// Get the GraphQL subscriptions client.
    ///
    /// Opens `graphql-transport-ws` WebSockets against either the
    /// validator's or an indexer's `/graphql/ws` endpoint, depending on
    /// the `source` in [`crate::subscriptions::SubscribeOptions`].
    pub fn subscriptions(&self) -> crate::subscriptions::WillowSubscriptions {
        crate::subscriptions::WillowSubscriptions::new(self.base_url.clone(), self.indexers.clone())
    }

    /// Get indexing operations (GraphQL, subgroves)
    pub fn indexing(&self) -> IndexingOperations {
        IndexingOperations::new(self.clone())
    }

    /// Set the verification policy for verifiable-RPC responses.
    ///
    /// Defaults to [`VerifyMode::Strict`]. Use [`VerifyMode::GroveDbOnly`] if
    /// you anchor state roots via the consensus light client yourself, and
    /// [`VerifyMode::Disabled`] only for local debugging.
    pub fn set_verify_mode(&self, mode: VerifyMode) {
        *self.verify_mode.write().unwrap() = mode;
    }

    /// Current verification policy.
    pub fn verify_mode(&self) -> VerifyMode {
        *self.verify_mode.read().unwrap()
    }

    /// Get verifiable-RPC operations.
    ///
    /// Requires the `verifiable-rpc` cargo feature. Without the feature,
    /// this method isn't compiled in — attempting to call it will fail to
    /// build with a clear "method not found" error rather than a runtime
    /// failure.
    #[cfg(feature = "verifiable-rpc")]
    pub fn verifiable_rpc(&self) -> crate::verifiable_rpc::VerifiableRpcOperations {
        crate::verifiable_rpc::VerifiableRpcOperations::new(self.clone())
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

    /// The consensus client, or a clear error naming `operation` when no consensus URL is set:
    /// a transaction has no server to go to without one.
    pub(crate) fn require_consensus(&self, operation: &str) -> Result<&ConsensusClient> {
        self.consensus_opt().ok_or_else(|| {
            WillowError::Config(format!(
                "{operation} submits a transaction and needs a consensus URL; set consensus_url(..) on the builder"
            ))
        })
    }

    /// Check the health of the Willow node
    pub async fn health(&self) -> Result<HealthStatus> {
        self.request("GET", "/health", None::<&()>, false).await
    }

    /// Get the root hash the API reports as committed (`GET /state/root-hash/verified`).
    ///
    /// The API's word, unverified: this SDK checks no signature or proof of it. To check a proof
    /// against the chain, use the light client's [`LightClient::app_hash_after`], which reads the
    /// header from the CometBFT RPC.
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
    /// This method returns the root hash from the node's local state, as the API reports it
    /// (unverified, like [`Self::get_root_hash`]). Useful for debugging.
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

        // The body is serialized here so the signature covers the exact bytes sent.
        let body_bytes = match body {
            Some(body_data) => Some(serde_json::to_vec(body_data)?),
            None => None,
        };

        // A read with rights is signed with a fresh nonce on every attempt; any
        // other request keeps the older form, which the server also accepts in
        // the first 30 s after a restart, when it refuses nonce-signed requests.
        let target = self.api_target(&url);
        let headers = if carries_read_rights(method, &target) {
            self.sign_request_with_nonce(method, &url, body_bytes.as_deref().unwrap_or(&[]))?
        } else {
            self.sign_request(method, &target)
        };
        match headers {
            Some(headers) => {
                for (key, value) in headers {
                    request = request.header(&key, &value);
                }
            }
            None if authenticated => return Err(WillowError::NotAuthenticated),
            None => {}
        }

        if let Some(bytes) = body_bytes {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes);
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

/// Whether a request is a read of subgrove data, the reads the API can gate by a
/// DID's read rights: `GET /data/{sg}/{key}`, `GET /proof/{sg}/{key}`,
/// `POST /query/{sg}`, `/sql/{sg}`, `/graphql/{sg}`, and `POST /a2a`. Only these are
/// nonce-signed.
pub(crate) fn carries_read_rights(method: &str, target: &str) -> bool {
    let path = target.split('?').next().unwrap_or(target);
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    matches!(
        (method, segments.as_slice()),
        ("GET", ["data" | "proof", _, _])
            | ("POST", ["query" | "sql" | "graphql", _])
            | ("POST", ["a2a"])
    )
}

/// Builder for WillowClient
pub struct WillowClientBuilder {
    api_url: Option<String>,
    consensus_url: Option<String>,
    indexer_url: Option<String>,
    api_key: Option<String>,
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
            indexer_url: None,
            api_key: None,
            timeout: DEFAULT_TIMEOUT,
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
    /// Required for consensus operations like DID registration, subgrove registration,
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

    /// Set an optional indexer node URL.
    ///
    /// When set, GraphQL and SQL queries are routed to this indexer node
    /// instead of the validator API. This enables querying indexed data
    /// directly from a decentralized indexer. The indexer-only routes
    /// (`eth()`, `verifiable_rpc()`, and `verify_block_completeness`) need it.
    ///
    /// # Example
    /// ```rust,no_run
    /// use willow_sdk::WillowClient;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = WillowClient::builder()
    ///         .api_url("http://localhost:3031")
    ///         .indexer_url("http://localhost:8090")
    ///         .build()
    ///         .await?;
    ///     Ok(())
    /// }
    /// ```
    pub fn indexer_url(mut self, url: &str) -> Self {
        self.indexer_url = Some(url.to_string());
        self
    }

    /// Set the managed-tier API key (`wk_…`).
    ///
    /// When set, the SDK sends `X-API-Key: <api_key>` on every request as
    /// a default reqwest header. Mint a key at
    /// <https://dashboard.willow.tech/account>. Required for queries and
    /// writes against managed `api.willow.tech` / `indexer.willow.tech`.
    pub fn api_key(mut self, key: &str) -> Self {
        self.api_key = Some(key.to_string());
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

        // Parse optional indexer URL
        let indexer_url = self
            .indexer_url
            .map(|url| parse_api_url(&url))
            .transpose()?;

        let mut http_builder = Client::builder().timeout(self.timeout);
        if let Some(api_key) = &self.api_key {
            let mut headers = reqwest::header::HeaderMap::new();
            let value = reqwest::header::HeaderValue::from_str(api_key).map_err(|e| {
                WillowError::Config(format!("invalid API key (non-ASCII header value): {}", e))
            })?;
            headers.insert("X-API-Key", value);
            http_builder = http_builder.default_headers(headers);
        }
        let http_client = http_builder
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
        let consensus_client = self.consensus_url.map(|url| {
            Arc::new(
                ConsensusClient::new_with_api(&url, base_url.as_str())
                    .with_http_client(http_client_with_timeout(self.timeout)),
            )
        });

        let indexers =
            WillowIndexers::new(http_client.clone(), base_url.clone(), indexer_url.clone());

        Ok(WillowClient {
            http_client,
            timeout: self.timeout,
            base_url,
            indexer_url,
            indexers,
            identity: Arc::new(RwLock::new(None)),
            retry_config: self.retry_config,
            #[cfg(not(feature = "no-light-client"))]
            light_client,
            #[cfg(not(feature = "no-light-client"))]
            light_client_once: Arc::new(OnceCell::new()),
            consensus_client,
            state_root_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
            verify_mode: Arc::new(RwLock::new(VerifyMode::default())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without a consensus URL, only an API on a loopback host at port 3031 implies the node
    /// whose app hash verified reads trust (the same host at port 26657).
    #[cfg(not(feature = "no-light-client"))]
    #[tokio::test]
    async fn only_a_loopback_api_implies_its_consensus_node() {
        for api in [
            "http://api.example.invalid:3031",
            "https://api.example.invalid",
        ] {
            let client = WillowClient::new(api).await.unwrap();
            let err = client.get_or_create_light_client().await.err().unwrap();
            assert!(matches!(err, WillowError::Config(_)), "{api}: {err}");
        }
        for (api, rpc) in [
            ("http://localhost:3031", Some("http://localhost:26657")),
            ("http://127.0.0.1:3031/", Some("http://127.0.0.1:26657")),
            ("http://[::1]:3031", Some("http://[::1]:26657")),
            ("http://localhost:8080", None),
            ("http://10.0.0.5:3031", None),
            ("https://api.willow.tech", None),
        ] {
            assert_eq!(
                local_consensus_rpc(&Url::parse(api).unwrap()).as_deref(),
                rpc,
                "{api}"
            );
        }
    }

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
        assert_eq!(
            client.get_did(),
            Some("did:willow:Ed25519:abc123".to_string())
        );

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

    fn received_header(req: &wiremock::Request, name: &str) -> String {
        req.headers
            .iter()
            .find(|(k, _)| k.as_str().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.last().as_str().to_string())
            .unwrap_or_default()
    }

    /// What the server verifies: the eight lines rebuilt from the request it got.
    fn assert_nonce_signed(req: &wiremock::Request, public_key_hex: &str) {
        let mut target = req.url.path().to_string();
        if let Some(q) = req.url.query() {
            target.push('?');
            target.push_str(q);
        }
        let message = crate::auth::signed_request_message(
            &received_header(req, "x-did"),
            &received_header(req, "x-public-key-id"),
            &req.method.to_string(),
            &target,
            &received_header(req, "x-timestamp"),
            &received_header(req, "x-nonce"),
            &req.body,
        );
        assert!(
            crate::auth::verify_signature(
                &message,
                &received_header(req, "x-signature"),
                public_key_hex,
                SignatureAlgorithm::Ed25519,
            )
            .unwrap(),
            "signature does not cover {} {} as received",
            req.method,
            target
        );
    }

    /// Requests to the API are signed with a one-time nonce over the request as
    /// sent, and a retried request is signed anew.
    #[tokio::test]
    async fn api_requests_are_nonce_signed_and_retries_resigned() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/query/sg"))
            .respond_with(ResponseTemplate::new(502))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/query/sg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/data/sg/k"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/subgroves"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let client = WillowClient::builder()
            .api_url(&server.uri())
            .retry_config(RetryConfig {
                max_attempts: 3,
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(1),
                exponential_base: 1.0,
            })
            .build()
            .await
            .unwrap();
        let seed = "0303030303030303030303030303030303030303030303030303030303030303";
        client.set_identity_with_algorithm(
            "did:willow:a",
            seed,
            "did:willow:a#key-1",
            SignatureAlgorithm::Ed25519,
        );
        let public_key = "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1";

        let _: serde_json::Value = client
            .request(
                "POST",
                "/query/sg?x=1",
                Some(&serde_json::json!({"limit": 1})),
                true,
            )
            .await
            .unwrap();
        let _: serde_json::Value = client
            .request::<_, ()>("GET", "/data/sg/k", None, true)
            .await
            .unwrap();

        let _: serde_json::Value = client
            .request::<_, ()>("GET", "/subgroves?x=1", None, true)
            .await
            .unwrap();

        let received = server.received_requests().await.unwrap();
        assert_eq!(
            received.len(),
            4,
            "the failed POST, its retry, the GET, and the listing"
        );
        for req in &received[..3] {
            assert_nonce_signed(req, public_key);
        }
        // Not a read with rights: the older form, over the path without its query.
        let listing = &received[3];
        assert_eq!(received_header(listing, "x-nonce"), "");
        let message = crate::auth::legacy_request_message(
            "GET",
            listing.url.path(),
            &received_header(listing, "x-timestamp"),
        );
        assert!(crate::auth::verify_signature(
            &message,
            &received_header(listing, "x-signature"),
            public_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap());
        assert_eq!(received[0].body, br#"{"limit":1}"#.to_vec());
        assert_eq!(
            received[1].body, received[0].body,
            "the retry keeps its body"
        );
        assert_ne!(
            received_header(&received[0], "x-nonce"),
            received_header(&received[1], "x-nonce"),
            "a retry must carry a new nonce"
        );
    }

    /// GraphQL sent to the API is nonce-signed over its body; sent to an indexer it
    /// carries no nonce.
    #[tokio::test]
    async fn graphql_is_nonce_signed_only_toward_the_api() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql/sg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": {}})))
            .mount(&server)
            .await;
        let seed = "0303030303030303030303030303030303030303030303030303030303030303";
        let public_key = "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1";

        let to_api = WillowClient::new(&server.uri()).await.unwrap();
        let to_indexer = WillowClient::builder()
            .api_url("http://127.0.0.1:1")
            .indexer_url(&server.uri())
            .build()
            .await
            .unwrap();
        for client in [&to_api, &to_indexer] {
            client.set_identity_with_algorithm(
                "did:willow:a",
                seed,
                "did:willow:a#key-1",
                SignatureAlgorithm::Ed25519,
            );
            client
                .indexing()
                .graphql_query("sg", "{ items { id } }", None)
                .await
                .unwrap();
        }

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 2);
        assert_nonce_signed(&received[0], public_key);
        assert_eq!(received_header(&received[1], "x-nonce"), "");
    }

    #[test]
    fn only_reads_with_rights_are_nonce_signed() {
        for (method, target, want) in [
            ("GET", "/data/sg/k", true),
            ("GET", "/data/sg/k?x=1", true),
            ("GET", "/proof/sg/k", true),
            ("POST", "/query/sg", true),
            ("POST", "/sql/sg", true),
            ("POST", "/graphql/sg", true),
            ("POST", "/a2a", true),
            ("GET", "/proof/key-grant/sg/did:willow:a", false),
            ("GET", "/proof/file/sg/k", false),
            ("GET", "/subgroves", false),
            ("PUT", "/data/sg/k", false),
            ("POST", "/tx/submit", false),
            ("GET", "/did/did:willow:a/permissions", false),
        ] {
            assert_eq!(
                carries_read_rights(method, target),
                want,
                "{method} {target}"
            );
        }
    }

    #[tokio::test]
    async fn api_target_drops_the_base_url_path() {
        let client = WillowClient::new("https://proxy.example/willow")
            .await
            .unwrap();
        let url = client.base_url.join("data/sg/k?x=1").unwrap();
        assert_eq!(url.as_str(), "https://proxy.example/willow/data/sg/k?x=1");
        assert_eq!(client.api_target(&url), "/data/sg/k?x=1");
    }

    /// Reconstruct the message that `sign_request` signed from the headers it
    /// emitted, so a test can independently verify the produced signature.
    fn message_from_headers(method: &str, path: &str, headers: &[(String, String)]) -> String {
        let map: std::collections::HashMap<_, _> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        format!("{}:{}:{}", method, path, map["X-Timestamp"])
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .unwrap()
    }

    /// A self-certifying secp256k1 identity must sign with secp256k1, not the
    /// Ed25519 default. `did:willow:z...` ids do not encode their algorithm, so
    /// the explicit-algorithm setter is what makes this correct.
    #[tokio::test]
    async fn test_set_identity_with_algorithm_selects_secp256k1() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        let did_info = crate::auth::generate_did(SignatureAlgorithm::Secp256k1).unwrap();
        // Sanity: the id is self-certifying (no parseable algorithm).
        assert!(did_info.did.starts_with("did:willow:z"));

        client.set_identity_with_algorithm(
            &did_info.did,
            &did_info.private_key_hex(),
            &did_info.public_key_id,
            SignatureAlgorithm::Secp256k1,
        );

        // The stored identity carries secp256k1, not the Ed25519 default.
        let stored = client.identity.read().unwrap().as_ref().unwrap().algorithm;
        assert_eq!(stored, SignatureAlgorithm::Secp256k1);

        // End-to-end: the per-request signature verifies under secp256k1.
        let headers = client
            .sign_request("GET", "/v1/data")
            .expect("signed headers");
        let message = message_from_headers("GET", "/v1/data", &headers);
        assert!(crate::auth::verify_signature(
            &message,
            header(&headers, "X-Signature"),
            &did_info.public_key_hex(),
            SignatureAlgorithm::Secp256k1,
        )
        .unwrap());
    }

    /// `set_identity_from_did_info` takes the algorithm straight from `DidInfo`,
    /// so a secp256k1 identity signs with secp256k1 without any string parsing.
    #[tokio::test]
    async fn test_set_identity_from_did_info_secp256k1() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        let did_info = crate::auth::generate_did(SignatureAlgorithm::Secp256k1).unwrap();

        client.set_identity_from_did_info(&did_info);

        let stored = client.identity.read().unwrap().as_ref().unwrap().algorithm;
        assert_eq!(stored, SignatureAlgorithm::Secp256k1);

        let headers = client
            .sign_request("POST", "/v1/store")
            .expect("signed headers");
        let message = message_from_headers("POST", "/v1/store", &headers);
        assert!(crate::auth::verify_signature(
            &message,
            header(&headers, "X-Signature"),
            &did_info.public_key_hex(),
            SignatureAlgorithm::Secp256k1,
        )
        .unwrap());
    }

    /// Regression guard for the bug this fix addresses: routing a secp256k1 key
    /// through the algorithm-guessing `set_identity` on a self-certifying id
    /// defaults to Ed25519 and therefore signs with the WRONG scheme — the
    /// resulting signature does not verify as secp256k1. This is exactly why the
    /// explicit-algorithm setters exist.
    #[tokio::test]
    async fn test_default_set_identity_mis_signs_secp256k1_key() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        let did_info = crate::auth::generate_did(SignatureAlgorithm::Secp256k1).unwrap();

        client.set_identity(
            &did_info.did,
            &did_info.private_key_hex(),
            &did_info.public_key_id,
        );

        // The guess defaulted to Ed25519 for the self-certifying id.
        let stored = client.identity.read().unwrap().as_ref().unwrap().algorithm;
        assert_eq!(stored, SignatureAlgorithm::Ed25519);

        // So the request is signed as Ed25519 and does NOT verify as secp256k1.
        let headers = client
            .sign_request("GET", "/v1/data")
            .expect("signed headers");
        let message = message_from_headers("GET", "/v1/data", &headers);
        let secp_ok = crate::auth::verify_signature(
            &message,
            header(&headers, "X-Signature"),
            &did_info.public_key_hex(),
            SignatureAlgorithm::Secp256k1,
        )
        .unwrap_or(false);
        assert!(!secp_ok);
    }

    /// Ed25519 still defaults correctly through the plain `set_identity`.
    #[tokio::test]
    async fn test_set_identity_defaults_ed25519_for_self_certifying() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        let did_info = crate::auth::generate_did(SignatureAlgorithm::Ed25519).unwrap();

        client.set_identity(
            &did_info.did,
            &did_info.private_key_hex(),
            &did_info.public_key_id,
        );

        let stored = client.identity.read().unwrap().as_ref().unwrap().algorithm;
        assert_eq!(stored, SignatureAlgorithm::Ed25519);

        let headers = client
            .sign_request("GET", "/v1/data")
            .expect("signed headers");
        let message = message_from_headers("GET", "/v1/data", &headers);
        assert!(crate::auth::verify_signature(
            &message,
            header(&headers, "X-Signature"),
            &did_info.public_key_hex(),
            SignatureAlgorithm::Ed25519,
        )
        .unwrap());
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
