//! Data operations for Willow

use crate::client::WillowClient;
use crate::errors::{Result, WillowError};
use crate::types::ApiResponse;
use serde::{Deserialize, Serialize};
use serde_json::Value;
/// Response from a query operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    pub documents: Vec<Value>,
    pub total: Option<usize>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// Never set by this SDK: a query's documents are returned unverified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_root_hash: Option<String>,
}

// ============================================================================
// Historical Query Types (for checkpoint data)
// ============================================================================

/// Information about a verified checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointInfo {
    /// Checkpoint ID (hex)
    pub checkpoint_id: String,
    /// Subgrove ID
    pub subgrove_id: String,
    /// State root hash (hex)
    pub state_root: String,
    /// Block range [start, end]
    pub block_range: (u64, u64),
    /// Whether the checkpoint is trusted
    pub is_trusted: bool,
}

/// Request for a historical query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalQueryRequest {
    /// GroveDB path to query (as byte arrays)
    pub path: Vec<Vec<u8>>,
    /// Key to query (for single-key queries)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<Vec<u8>>,
    /// Query type: "get", "get_range", "get_path"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_type: Option<String>,
    /// Whether to include proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_proof: Option<bool>,
}

/// Response from a historical query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalQueryResponse {
    /// Whether the query was successful
    pub success: bool,
    /// Provider DID that served this query
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_did: Option<String>,
    /// Provider endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_endpoint: Option<String>,
    /// The checkpoint's state root as its indexer submitted it (not necessarily a data root)
    pub state_root: String,
    /// Block range covered by the checkpoint
    pub block_range: (u64, u64),
    /// Query results from the indexer
    pub data: Value,
    /// The provider's GroveDB proof (hex) of its own store, not checked against the checkpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// Whether this data can be re-indexed (only set on error)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_reindex: Option<bool>,
    /// Error message if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A value [`DataOperations::get_verified`] verified, and the height it is proven at.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedValue {
    /// The value its proof binds at the key.
    pub value: Value,
    /// The height of the CometBFT header whose app hash the proof's root is: the value is the
    /// chain's state as of that header (the state after block `height - 1`), not necessarily
    /// as of now.
    pub height: u64,
}

/// Data operations
pub struct DataOperations {
    client: WillowClient,
}

impl DataOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Get a single item from a subgrove, verified: [`Self::get_verified`]'s value.
    pub async fn get(&self, subgrove_id: &str, key: &str) -> Result<Value> {
        self.get_verified(subgrove_id, key)
            .await
            .map(|verified| verified.value)
    }

    /// Get a single item from a subgrove, verified, with the height it is proven at.
    ///
    /// Reads the value (`GET /data/{subgrove}/{key}`) and its proof (`GET /proof/{subgrove}/{key}`),
    /// and returns the value only when:
    ///
    /// - the proof proves an Item at `key` in the subgrove's data tree
    ///   (`[subgroves, subgrove_id, data]`), in a form its root binds
    ///   ([`crate::grovedb_envelope::verify_item_at_path`]), and that item is the value served;
    /// - the root the proof computes is the app hash of the CometBFT header at the proof's
    ///   height plus one (the state after block `height` is committed in the next block's
    ///   header), as the light client gives it from its validator endpoints;
    /// - the state is recent: the API chooses the height it proves at, so a state more than the
    ///   light client's `max_proof_lag_blocks` (default 20) behind the chain's latest height is
    ///   refused as [`WillowError::ProofHeightOutOfRange`] unless a header within that lag still
    ///   carries the same root (a chain with no transactions since keeps its app hash), as is a
    ///   height that far ahead ([`crate::light_client::LightClient::verify_root_after`]).
    ///
    /// The returned height is that of the header found to carry the root: the value is the
    /// chain's state as of that header, and may have changed since.
    ///
    /// A missing proof or height, another value, or another root is a
    /// [`WillowError::ProofVerificationFailed`], and a header the light client can't get a
    /// light-client error: nothing is returned unverified. A key the API reports missing is
    /// [`WillowError::NotFound`], unproven. Built with `no-light-client`, this returns
    /// [`WillowError::Unsupported`]; use [`Self::get_unverified`].
    pub async fn get_verified(&self, subgrove_id: &str, key: &str) -> Result<VerifiedValue> {
        self.ensure_authenticated()?;

        let data_response: ApiResponse<Value> = self
            .client
            .request(
                "GET",
                &format!("/data/{}/{}", subgrove_id, key),
                None::<&()>,
                true,
            )
            .await?;

        let data = data_response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("Key not found: {}", key)))?;

        #[cfg(not(feature = "no-light-client"))]
        {
            let proof_response: ApiResponse<Value> = self
                .client
                .request(
                    "GET",
                    &format!("/proof/{}/{}", subgrove_id, key),
                    None::<&()>,
                    true,
                )
                .await?;
            let fail = |m: String| WillowError::ProofVerificationFailed(m);
            let proof_data = proof_response.data.ok_or_else(|| {
                fail(format!(
                    "no proof served for key {key:?}, so the value can't be verified (use \
                     get_unverified to read it unverified)"
                ))
            })?;
            let proof_hex = proof_data
                .get("proof")
                .and_then(|p| p.as_str())
                .ok_or_else(|| {
                    fail(format!(
                        "the proof served for key {key:?} has no proof bytes"
                    ))
                })?;
            let height = proof_data
                .get("height")
                .and_then(|h| h.as_u64())
                .filter(|h| *h > 0)
                .ok_or_else(|| {
                    fail(format!(
                        "the proof served for key {key:?} names no block height, so its root \
                         can't be checked against the chain's"
                    ))
                })?;
            let max_hex = 2 * crate::grovedb_envelope::MAX_PROOF_BYTES;
            if proof_hex.len() > max_hex {
                return Err(fail(format!(
                    "the proof served for key {key:?} is {} hex characters; at most {max_hex} \
                     are accepted",
                    proof_hex.len()
                )));
            }
            let proof =
                hex::decode(proof_hex).map_err(|e| fail(format!("Invalid proof hex: {e}")))?;

            let path = crate::proof::subgrove_data_path(subgrove_id);
            let (root, item) =
                crate::grovedb_envelope::verify_item_at_path(&proof, &path, key.as_bytes())?;
            let proven = served_value(&item);
            if proven != data {
                return Err(fail(format!(
                    "the value served for key {key:?} is not the value its proof proves"
                )));
            }

            let light_client = self.client.get_or_create_light_client().await?;
            let height = light_client.verify_root_after(&root, height).await?;
            Ok(VerifiedValue {
                value: proven,
                height,
            })
        }

        #[cfg(feature = "no-light-client")]
        {
            let _ = data;
            Err(WillowError::Unsupported(
                "built with no-light-client, the SDK can't verify a read; use get_unverified"
                    .to_string(),
            ))
        }
    }

    /// Get a single item without proof verification
    pub async fn get_unverified(&self, subgrove_id: &str, key: &str) -> Result<Value> {
        self.ensure_authenticated()?;

        let response: ApiResponse<Value> = self
            .client
            .request(
                "GET",
                &format!("/data/{}/{}", subgrove_id, key),
                None::<&()>,
                true,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("Key not found: {}", key)))
    }

    /// Not supported: always [`WillowError::Unsupported`], with nothing sent.
    ///
    /// The API returns a query's documents without their keys, with a proof of the subgrove's
    /// whole data tree, so nothing binds the documents to the proof, nor to the query's filter,
    /// order, offset, and limit. Use [`Self::query_unverified`] for the documents unverified, or
    /// [`Self::get`] for a verified value by key.
    pub async fn query(&self, subgrove_id: &str, query: Value) -> Result<QueryResponse> {
        let _ = (subgrove_id, query);
        self.ensure_authenticated()?;
        Err(WillowError::Unsupported(
            "a query's documents can't be verified: the API serves them without their keys, \
             and nothing binds them to the proof or to the query's selection; use \
             query_unverified, or get for a verified value by key"
                .to_string(),
        ))
    }

    /// Execute a SQL query against a subgrove. Sends to
    /// [`WillowClient::indexer_base_url`] — the explicit `indexer_url`
    /// override if set, else the validator. For source-routed queries
    /// use [`Self::sql_with_source`].
    ///
    /// Works with both DataStorage and BlockchainIndexing subgroves.
    /// For DataStorage, the table name in FROM is ignored — all documents
    /// are the dataset. Standard SQL: WHERE, ORDER BY, LIMIT, OFFSET,
    /// column projection, COUNT(*).
    pub async fn sql(&self, subgrove_id: &str, query: &str) -> Result<crate::types::SqlResponse> {
        self.ensure_authenticated()?;

        let request = crate::types::SqlRequest {
            query: query.to_string(),
            // Display/SQL path is an unverified read: opt out of proofs on the
            // wire so the server doesn't default to include_proof=true.
            include_proof: Some(false),
        };

        let base = self.client.indexer_base_url();
        let url = base
            .join(&format!("sql/{}", subgrove_id))
            .map_err(|e| WillowError::Config(format!("Invalid URL: {}", e)))?;

        let body = serde_json::to_vec(&request)?;
        let mut req = self
            .client
            .http_client
            .post(url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.clone());
        // Sent to the API, it is nonce-signed so it carries the identity's read rights.
        if self.client.queries_go_to_api() {
            if let Some(headers) = self.client.sign_request_with_nonce("POST", &url, &body)? {
                for (k, v) in headers {
                    req = req.header(&k, &v);
                }
            }
        }
        let http_resp = req.send().await?;

        let status = http_resp.status();
        let text = crate::http_body::text(http_resp, crate::http_body::LARGE).await?;

        if status.is_success() {
            crate::http_body::decode_checked(&text, crate::http_body::JsonBudget::UnderProof)
        } else {
            Err(WillowError::Http {
                status: status.as_u16(),
                message: text,
            })
        }
    }

    /// Execute a SQL query with explicit source selection.
    ///
    /// See [`crate::indexers::QuerySource`] for the routing semantics.
    /// The returned [`crate::indexers::RoutedQueryResult`] tells the caller
    /// which backend actually served the query.
    pub async fn sql_with_source(
        &self,
        subgrove_id: &str,
        query: &str,
        source: crate::indexers::QuerySource,
    ) -> Result<crate::indexers::RoutedQueryResult<crate::types::SqlResponse>> {
        self.ensure_authenticated()?;

        let request = crate::types::SqlRequest {
            query: query.to_string(),
            // Unverified SQL read: opt out of proofs on the wire so the server
            // doesn't default to include_proof=true.
            include_proof: Some(false),
        };

        // The shared routing helper lives on IndexingOperations so both
        // `graphql_query_with_source` and `sql_with_source` go through the
        // same code path — single source of truth for the routing behaviour.
        self.client
            .indexing()
            .route("sql", subgrove_id, &request, source)
            .await
    }

    /// Query items without proof verification for performance-critical cases
    ///
    /// Use this method when you need maximum performance and are willing to trust
    /// the node without cryptographic verification.
    pub async fn query_unverified(
        &self,
        subgrove_id: &str,
        mut query: Value,
    ) -> Result<QueryResponse> {
        self.ensure_authenticated()?;

        // Explicitly disable proof for performance
        if let Some(obj) = query.as_object_mut() {
            obj.insert("include_proof".to_string(), Value::Bool(false));
        }

        let response: ApiResponse<QueryResponse> = self
            .client
            .request(
                "POST",
                &format!("/query/{}", subgrove_id),
                Some(&query),
                true,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::Custom("No data in query response".to_string()))
    }

    // ============================================================================
    // Historical Query Methods
    // ============================================================================

    /// Get a checkpoint's state root, as the API reports it (unproven).
    ///
    /// # Arguments
    ///
    /// * `subgrove_id` - The subgrove ID
    /// * `checkpoint_id` - The checkpoint ID (hex string)
    ///
    /// # Returns
    ///
    /// Checkpoint info including state root for verification
    pub async fn get_checkpoint_state_root(
        &self,
        subgrove_id: &str,
        checkpoint_id: &str,
    ) -> Result<CheckpointInfo> {
        let response: ApiResponse<CheckpointInfo> = self
            .client
            .request(
                "GET",
                &format!("/checkpoints/{}/{}/state-root", subgrove_id, checkpoint_id),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound("Checkpoint not found".to_string()))
    }

    /// Query historical indexed data from a checkpoint, unverified.
    ///
    /// This method queries historical data from indexer nodes that have preserved
    /// checkpoint data, through the API. The answer is not verified: the API passes the
    /// provider's proof through (`proof`, hex) without checking it against the checkpoint, and
    /// nothing requires the checkpoint's state root to commit to the provider's store (the
    /// reference indexer's is a SHA-256 of the subgrove id, block range, and entity count, not a
    /// root of the data). The state root it is compared with comes from the same API
    /// ([`Self::get_checkpoint_state_root`]); a response whose state root differs from that
    /// checkpoint's is refused as inconsistent.
    ///
    /// # Arguments
    ///
    /// * `subgrove_id` - The subgrove ID
    /// * `checkpoint_id` - The checkpoint ID (hex string)
    /// * `query` - The query parameters
    ///
    /// # Returns
    ///
    /// Historical query response with provider info and verification data
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use willow_sdk::data::{HistoricalQueryRequest, DataOperations};
    ///
    /// async fn example(data_ops: &DataOperations) {
    ///     let query = HistoricalQueryRequest {
    ///         path: vec![b"subgroves".to_vec(), b"data".to_vec()],
    ///         key: Some(b"key123".to_vec()),
    ///         query_type: Some("get".to_string()),
    ///         include_proof: Some(true),
    ///     };
    ///
    ///     let response = data_ops
    ///         .query_historical("my-subgrove", "0abc...", query)
    ///         .await
    ///         .unwrap();
    ///
    ///     println!("Provider: {:?}", response.provider_did);
    ///     println!("State root: {}", response.state_root);
    /// }
    /// ```
    pub async fn query_historical(
        &self,
        subgrove_id: &str,
        checkpoint_id: &str,
        query: HistoricalQueryRequest,
    ) -> Result<HistoricalQueryResponse> {
        // First, verify the checkpoint exists and get its state root
        let checkpoint = self
            .get_checkpoint_state_root(subgrove_id, checkpoint_id)
            .await?;

        // Make the historical query
        let response: HistoricalQueryResponse = self
            .client
            .request(
                "POST",
                &format!("/historical/query/{}/{}", subgrove_id, checkpoint_id),
                Some(&query),
                false,
            )
            .await?;

        // If query failed due to no providers, return error with can_reindex info
        if !response.success {
            let error_msg = response
                .error
                .clone()
                .unwrap_or_else(|| "Historical query failed".to_string());
            if response.can_reindex == Some(true) {
                return Err(WillowError::HistoricalDataUnavailable {
                    message: error_msg,
                    can_reindex: true,
                });
            }
            return Err(WillowError::Custom(error_msg));
        }

        // Verify the returned state root matches the checkpoint
        if response.state_root != checkpoint.state_root {
            return Err(WillowError::ProofVerificationFailed(
                "State root mismatch: query response does not match checkpoint".to_string(),
            ));
        }

        Ok(response)
    }

    /// Not supported: always [`WillowError::Unsupported`], with nothing sent.
    ///
    /// The API passes the provider's proof through without checking it against the
    /// checkpoint, and nothing requires the checkpoint's state root to commit to the provider's
    /// store, so the proof shows nothing about the checkpoint. Use [`Self::query_historical`]
    /// for the answer unverified.
    #[deprecated(
        note = "a historical answer can't be verified: the API doesn't check the provider's \
                proof against the checkpoint, and nothing requires the checkpoint root to commit \
                to the provider's store; use query_historical for it unverified"
    )]
    pub async fn query_historical_verified(
        &self,
        subgrove_id: &str,
        checkpoint_id: &str,
        query: HistoricalQueryRequest,
    ) -> Result<HistoricalQueryResponse> {
        let _ = (subgrove_id, checkpoint_id, query);
        Err(WillowError::Unsupported(
            "a historical answer can't be verified: the API passes the provider's proof through \
             without checking it against the checkpoint, and nothing requires the checkpoint's \
             state root to commit to the provider's store; use query_historical for it unverified"
                .to_string(),
        ))
    }

    fn ensure_authenticated(&self) -> Result<()> {
        self.client.require_auth()
    }
}

/// The value `GET /data` serves for an item's bytes: their JSON, or `{"hex": <hex>}` when
/// they aren't JSON.
#[cfg(not(feature = "no-light-client"))]
fn served_value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes)
        .unwrap_or_else(|_| serde_json::json!({ "hex": hex::encode(bytes) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "no-light-client"))]
    mod verified_get {
        use super::*;
        use crate::grovedb_envelope::test_proofs::item_proof;
        use crate::light_client::LightClientConfig;
        use crate::types::SignatureAlgorithm;
        use serde_json::json;
        use std::time::Duration;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const SG: &str = "sg-1";
        const KEY: &str = "doc1";
        const HEIGHT: u64 = 41;

        fn value() -> Value {
            json!({"title": "Hello", "n": 42})
        }

        /// The CometBFT `/commit` answer for a header at `height` with `app_hash`.
        fn commit(height: u64, app_hash: &[u8]) -> Value {
            json!({"jsonrpc": "2.0", "id": -1, "result": {"signed_header": {"header": {
                "chain_id": "willow", "height": height.to_string(),
                "app_hash": hex::encode_upper(app_hash)
            }}}})
        }

        /// An API serving `served` at the key with `proof`, and a CometBFT RPC whose header at
        /// HEIGHT + 1 has `app_hash` (and at HEIGHT, another), and whose latest height is
        /// HEIGHT + 1.
        async fn chain(served: Value, proof: Value, app_hash: &[u8]) -> (MockServer, WillowClient) {
            chain_with(
                served,
                proof,
                &[(HEIGHT + 1, app_hash.to_vec()), (HEIGHT, vec![0xee; 32])],
                HEIGHT + 1,
            )
            .await
        }

        /// An API serving `served` at the key with `proof`, and a CometBFT RPC with `headers`
        /// (height, app hash) and `latest` as its latest height.
        async fn chain_with(
            served: Value,
            proof: Value,
            headers: &[(u64, Vec<u8>)],
            latest: u64,
        ) -> (MockServer, WillowClient) {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(format!("/data/{SG}/{KEY}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"success": true, "data": served})),
                )
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/proof/{SG}/{KEY}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"success": true, "data": proof})),
                )
                .mount(&server)
                .await;
            for (height, app_hash) in headers {
                Mock::given(method("GET"))
                    .and(path("/commit"))
                    .and(query_param("height", height.to_string()))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(commit(*height, app_hash)),
                    )
                    .mount(&server)
                    .await;
            }
            Mock::given(method("GET"))
                .and(path("/status"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0", "id": -1,
                    "result": {"sync_info": {"latest_block_height": latest.to_string()}}
                })))
                .mount(&server)
                .await;
            let client = WillowClient::builder()
                .api_url(&server.uri())
                .light_client_config(
                    LightClientConfig::builder("willow")
                        .validator_endpoints(vec![server.uri()])
                        .rpc_timeout(Duration::from_millis(600))
                        .build(),
                )
                .build()
                .await
                .unwrap();
            client.set_identity_with_algorithm(
                "did:willow:a",
                &"03".repeat(32),
                "did:willow:a#key-1",
                SignatureAlgorithm::Ed25519,
            );
            (server, client)
        }

        fn honest() -> (Vec<u8>, [u8; 32]) {
            item_proof(
                &crate::proof::subgrove_data_path(SG),
                KEY.as_bytes(),
                &serde_json::to_vec(&value()).unwrap(),
            )
        }

        fn proof_body(proof: &[u8], height: Value) -> Value {
            json!({"proof": hex::encode(proof), "height": height, "path": [], "key": ""})
        }

        #[tokio::test]
        async fn get_returns_the_value_its_proof_binds_under_the_next_headers_app_hash() {
            let (proof, root) = honest();
            let (_server, client) = chain(value(), proof_body(&proof, json!(HEIGHT)), &root).await;
            assert_eq!(client.data().get(SG, KEY).await.unwrap(), value());
        }

        #[tokio::test]
        async fn get_refuses_what_it_cannot_verify() {
            let (proof, root) = honest();
            let refused = |result: Result<Value>| match result {
                Err(WillowError::ProofVerificationFailed(_)) | Err(WillowError::LightClient(_)) => {
                }
                other => panic!("expected a refusal, got {other:?}"),
            };

            // Another value served beside the honest proof.
            let (_s, client) = chain(
                json!({"title": "forged"}),
                proof_body(&proof, json!(HEIGHT)),
                &root,
            )
            .await;
            refused(client.data().get(SG, KEY).await);

            // The proof's root in the header at the proof's own height and another in the header
            // after it: the state after block H is in H + 1's header, so H's doesn't count.
            let (_s, client) = chain_with(
                value(),
                proof_body(&proof, json!(HEIGHT)),
                &[(HEIGHT, root.to_vec()), (HEIGHT + 1, vec![0x11; 32])],
                HEIGHT + 1,
            )
            .await;
            refused(client.data().get(SG, KEY).await);

            // No height, or no proof.
            let (_s, client) = chain(value(), proof_body(&proof, Value::Null), &root).await;
            refused(client.data().get(SG, KEY).await);
            let (_s, client) = chain(value(), json!({"height": HEIGHT}), &root).await;
            refused(client.data().get(SG, KEY).await);

            // A lone Push(Hash(root)), which names the trusted root itself.
            let lone = [&[0x00, 0x21, 0x01][..], &root, &[0x00, 0x01]].concat();
            let (_s, client) = chain(value(), proof_body(&lone, json!(HEIGHT)), &root).await;
            refused(client.data().get(SG, KEY).await);

            // A proof of the same value at another key or in another subgrove.
            let bytes = serde_json::to_vec(&value()).unwrap();
            for (path, key) in [
                (crate::proof::subgrove_data_path(SG), b"doc2".to_vec()),
                (
                    crate::proof::subgrove_data_path("sg-2"),
                    KEY.as_bytes().to_vec(),
                ),
            ] {
                let (other, other_root) = item_proof(&path, &key, &bytes);
                let (_s, client) =
                    chain(value(), proof_body(&other, json!(HEIGHT)), &other_root).await;
                refused(client.data().get(SG, KEY).await);
            }

            // No header after the proof's block.
            let (_s, client) = chain(value(), proof_body(&proof, json!(HEIGHT + 5)), &root).await;
            refused(client.data().get(SG, KEY).await);
        }

        #[tokio::test]
        async fn get_verified_gives_the_height_of_the_header_that_carries_the_root() {
            let (proof, root) = honest();
            let (_s, client) = chain(value(), proof_body(&proof, json!(HEIGHT)), &root).await;
            assert_eq!(
                client.data().get_verified(SG, KEY).await.unwrap(),
                VerifiedValue {
                    value: value(),
                    height: HEIGHT + 1
                }
            );
        }

        /// The API chooses the height it proves at: a state more than 20 blocks (the default
        /// lag) behind the latest is refused as out of range unless a header within the lag
        /// still carries its root.
        #[tokio::test]
        async fn a_stale_proof_is_refused_unless_the_chain_still_holds_its_state() {
            let (proof, root) = honest();
            let root = root.to_vec();
            let other = vec![0x22; 32];
            let latest = HEIGHT + 30;
            let oldest_recent = latest - 20 + 1;
            let get = |headers: Vec<(u64, Vec<u8>)>, latest: u64| {
                let proof = proof.clone();
                async move {
                    let (_s, client) =
                        chain_with(value(), proof_body(&proof, json!(HEIGHT)), &headers, latest)
                            .await;
                    client.data().get_verified(SG, KEY).await
                }
            };

            // The chain has changed the state since: stale, though the proof is genuine.
            let stale = get(
                vec![
                    (HEIGHT + 1, root.clone()),
                    (oldest_recent, other.clone()),
                    (latest, other.clone()),
                ],
                latest,
            )
            .await;
            assert!(
                matches!(stale, Err(WillowError::ProofHeightOutOfRange(_))),
                "{stale:?}"
            );

            // No transactions since: the latest header still carries the root.
            let held = get(
                vec![(HEIGHT + 1, root.clone()), (latest, root.clone())],
                latest,
            )
            .await
            .unwrap();
            assert_eq!(held.height, latest);

            // Changed within the lag: the oldest header within it still carries the root.
            let recent = get(
                vec![
                    (HEIGHT + 1, root.clone()),
                    (oldest_recent, root.clone()),
                    (latest, other.clone()),
                ],
                latest,
            )
            .await
            .unwrap();
            assert_eq!(recent.height, oldest_recent);

            // A root the header after the proof's block doesn't carry is forged, not stale.
            let forged = get(
                vec![(HEIGHT + 1, other.clone()), (latest, root.clone())],
                latest,
            )
            .await;
            assert!(
                matches!(forged, Err(WillowError::ProofVerificationFailed(_))),
                "{forged:?}"
            );

            // A height more than the lag ahead of the latest.
            let ahead = get(vec![(HEIGHT + 1, root.clone())], HEIGHT - 25).await;
            assert!(
                matches!(ahead, Err(WillowError::ProofHeightOutOfRange(_))),
                "{ahead:?}"
            );
        }

        #[tokio::test]
        async fn query_and_historical_verification_refuse_without_a_request() {
            let (proof, root) = honest();
            let (server, client) = chain(value(), proof_body(&proof, json!(HEIGHT)), &root).await;
            let before = server.received_requests().await.unwrap().len();
            assert!(matches!(
                client.data().query(SG, json!({})).await,
                Err(WillowError::Unsupported(_))
            ));
            #[allow(deprecated)]
            let historical = client
                .data()
                .query_historical_verified(
                    SG,
                    "00",
                    HistoricalQueryRequest {
                        path: vec![],
                        key: None,
                        query_type: None,
                        include_proof: None,
                    },
                )
                .await;
            assert!(matches!(
                historical,
                Err(WillowError::Unsupported(ref m))
                    if m.contains("without checking it against the checkpoint")
                        && m.contains("nothing requires the checkpoint's state root to commit")
            ));
            assert_eq!(server.received_requests().await.unwrap().len(), before);
        }

        /// Without a consensus URL or light-client config, an API URL that doesn't name port
        /// 3031 leaves no CometBFT RPC to read headers from: the API's own answer is no root.
        #[tokio::test]
        async fn no_header_source_but_the_api_is_a_configuration_error() {
            let client = WillowClient::new("https://api.example.invalid")
                .await
                .unwrap();
            let err = client.get_or_create_light_client().await.err().unwrap();
            assert!(matches!(err, WillowError::Config(_)), "{err}");
        }
    }

    #[tokio::test]
    async fn test_ensure_authenticated() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        let data_ops = client.data();

        // Should fail when not authenticated
        let result = data_ops.get("subgrove", "key").await;
        assert!(matches!(result, Err(WillowError::NotAuthenticated)));
    }
}
