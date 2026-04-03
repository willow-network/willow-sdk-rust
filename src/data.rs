//! Data operations for Willow

use crate::client::WillowClient;
use crate::errors::{Result, WillowError};
#[cfg(not(feature = "no-light-client"))]
use crate::proof::{ProofVerifier, QueryResponseExt};
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
    /// Checkpoint state root for proof verification
    pub state_root: String,
    /// Block range covered by the checkpoint
    pub block_range: (u64, u64),
    /// Query results from the indexer
    pub data: Value,
    /// Optional Merkle proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// Whether this data can be re-indexed (only set on error)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_reindex: Option<bool>,
    /// Error message if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Data operations
pub struct DataOperations {
    client: WillowClient,
}

impl DataOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Get a single item from a subgrove with automatic proof verification
    pub async fn get(&self, subgrove_id: &str, key: &str) -> Result<Value> {
        self.ensure_authenticated()?;

        // First get the data
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

        // Always verify proof using light client for trustless verification (default behavior).
        // The light client auto-initializes with trust-on-first-use if not already configured.
        //
        // Important: TODO: When mainnet/testnet launches, the light client will be
        // initialized with hardcoded checkpoint headers instead of trust-on-first-use.
        #[cfg(not(feature = "no-light-client"))]
        {
            // Get proof for this specific item
            let proof_response: ApiResponse<Value> = self
                .client
                .request(
                    "GET",
                    &format!("/proof/{}/{}", subgrove_id, key),
                    None::<&()>,
                    true,
                )
                .await?;

            if let Some(proof_data) = proof_response.data {
                if let Some(proof_hex) = proof_data.get("proof").and_then(|p| p.as_str()) {
                    // Get or create light client (auto-initializes with trust-on-first-use)
                    let light_client = self.client.get_or_create_light_client().await?;

                    // Build the GroveDB path matching the server's proof generation
                    let path: Vec<Vec<u8>> = vec![
                        b"subgroves".to_vec(),
                        subgrove_id.as_bytes().to_vec(),
                        b"data".to_vec(),
                    ];

                    light_client
                        .verify_proof_hex(proof_hex, &path, key.as_bytes(), None)
                        .await?;
                }
            } else {
                log::warn!("No proof available for key: {}", key);
            }
        }

        // When no-light-client feature is enabled, skip proof verification entirely
        // (user has explicitly opted out of trustless verification)

        Ok(data)
    }

    /// Get a single item without proof verification
    pub async fn get_unverified(
        &self,
        subgrove_id: &str,
        key: &str,
    ) -> Result<Value> {
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

    /// Query items using the indexing query API with automatic proof verification
    ///
    /// This method automatically requests proof and verifies it against the consensus root hash.
    /// If verification fails, the query will return an error.
    ///
    /// When `no-light-client` feature is enabled, this behaves the same as `query_unverified`.
    pub async fn query(
        &self,
        subgrove_id: &str,
        mut query: Value,
    ) -> Result<QueryResponse> {
        self.ensure_authenticated()?;

        // Only request proof if verification is enabled
        #[cfg(not(feature = "no-light-client"))]
        if let Some(obj) = query.as_object_mut() {
            obj.insert("include_proof".to_string(), Value::Bool(true));
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

        let mut query_response = response
            .data
            .ok_or_else(|| WillowError::Custom("No data in query response".to_string()))?;

        // Verify proof if present and light client is available
        #[cfg(not(feature = "no-light-client"))]
        if query_response.proof.is_some() {
            match self.verify_and_compare_root(subgrove_id, &query_response).await {
                Ok(verified_root) => {
                    query_response.verified_root_hash = Some(verified_root);
                }
                Err(e) => {
                    return Err(WillowError::ProofVerificationFailed(format!(
                        "Query proof verification failed: {}",
                        e
                    )));
                }
            }
        }

        Ok(query_response)
    }

    /// Execute a SQL query against a subgrove.
    ///
    /// Works with both DataStorage and BlockchainIndexing subgroves.
    /// For DataStorage, the table name in FROM is ignored — all documents
    /// are the dataset. Standard SQL: WHERE, ORDER BY, LIMIT, OFFSET,
    /// column projection, COUNT(*).
    pub async fn sql(
        &self,
        subgrove_id: &str,
        query: &str,
    ) -> Result<crate::types::SqlResponse> {
        self.ensure_authenticated()?;

        let request = crate::types::SqlRequest {
            query: query.to_string(),
            include_proof: None,
        };

        self.client
            .request(
                "POST",
                &format!("/sql/{}", subgrove_id),
                Some(&request),
                true,
            )
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

    /// Get checkpoint state root for proof verification.
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

    /// Query historical indexed data from a verified checkpoint.
    ///
    /// This method queries historical data from indexer nodes that have preserved
    /// checkpoint data. The response includes proof information that can be
    /// verified against the checkpoint's state root.
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

    /// Query historical data and verify the proof against checkpoint state root.
    ///
    /// This is the fully secure method for historical queries. It:
    /// 1. Gets the checkpoint state root from consensus
    /// 2. Executes the query through an indexer
    /// 3. Verifies the returned proof against the checkpoint state root
    ///
    /// # Arguments
    ///
    /// * `subgrove_id` - The subgrove ID
    /// * `checkpoint_id` - The checkpoint ID (hex string)
    /// * `query` - The query parameters (include_proof is forced to true)
    ///
    /// # Returns
    ///
    /// Verified historical data
    ///
    /// # Errors
    ///
    /// Returns an error if proof verification fails
    pub async fn query_historical_verified(
        &self,
        subgrove_id: &str,
        checkpoint_id: &str,
        mut query: HistoricalQueryRequest,
    ) -> Result<HistoricalQueryResponse> {
        // Force proof inclusion for verification
        query.include_proof = Some(true);

        let result = self
            .query_historical(subgrove_id, checkpoint_id, query)
            .await?;

        // Verify the proof against the checkpoint state root
        #[cfg(not(feature = "no-light-client"))]
        {
            if let Some(ref proof) = result.proof {
                // Convert data to array format for verification
                let documents = if result.data.is_array() {
                    result.data.as_array().unwrap().clone()
                } else {
                    vec![result.data.clone()]
                };

                // Verify proof and get computed root hash
                let computed_root = ProofVerifier::verify_query_proof(proof, &documents)?;

                // Compare with the checkpoint's state root (normalize hex strings)
                let normalized_computed = computed_root
                    .to_lowercase()
                    .trim_start_matches("0x")
                    .to_string();
                let normalized_expected = result
                    .state_root
                    .to_lowercase()
                    .trim_start_matches("0x")
                    .to_string();

                if normalized_computed != normalized_expected {
                    return Err(WillowError::ProofVerificationFailed(format!(
                        "Historical proof verification failed: computed root {} does not match checkpoint state root {}",
                        computed_root, result.state_root
                    )));
                }
            } else {
                // Proof was requested but not returned
                return Err(WillowError::ProofVerificationFailed(
                    "Historical query did not return proof data despite include_proof=true"
                        .to_string(),
                ));
            }
        }

        #[cfg(feature = "no-light-client")]
        {
            // Without light client, we can't verify proofs
            // Just warn and return the result
            eprintln!("Warning: proof verification disabled with 'no-light-client' feature");
        }

        Ok(result)
    }

    fn ensure_authenticated(&self) -> Result<()> {
        self.client.require_auth()
    }

    /// Verify proof and compare with consensus root hash.
    ///
    /// This method always uses the light client for trustless verification.
    /// The light client auto-initializes with trust-on-first-use if not already configured.
    ///
    /// Important: TODO: When mainnet/testnet launches, the light client will be
    /// initialized with hardcoded checkpoint headers instead of trust-on-first-use.
    ///
    /// Only available when light client verification is enabled.
    #[cfg(not(feature = "no-light-client"))]
    async fn verify_and_compare_root(
        &self,
        subgrove_id: &str,
        query_response: &QueryResponse,
    ) -> Result<String> {
        use grovedb::{GroveDb, PathQuery, Query};

        let light_client = self.client.get_or_create_light_client().await?;

        let proof_hex = query_response.proof.as_ref().ok_or_else(|| {
            WillowError::ProofVerificationFailed("No proof in query response".to_string())
        })?;

        let proof_bytes = hex::decode(proof_hex).map_err(|e| {
            WillowError::ProofVerificationFailed(format!("Invalid proof hex: {}", e))
        })?;
        if proof_bytes.is_empty() {
            return Err(WillowError::ProofVerificationFailed(
                "Empty proof".to_string(),
            ));
        }

        // Build the same PathQuery the server used to generate the proof:
        // path: [subgroves, subgrove_id, data], query: range_full
        // The server always generates proofs with range_full (matching full_scan),
        // so the SDK reconstructs the identical PathQuery for strict verification.
        let path: Vec<Vec<u8>> = vec![
            b"subgroves".to_vec(),
            subgrove_id.as_bytes().to_vec(),
            b"data".to_vec(),
        ];

        let query = Query::new_range_full();
        let path_query = PathQuery::new_unsized(path, query);
        let grove_version = grovedb_version::version::GroveVersion::default();

        // Strict verify_query — proves completeness: the server returned ALL
        // data in the subgrove. If any item was omitted or fabricated, this fails.
        let (computed_root_bytes, _verified_items) =
            GroveDb::verify_query(&proof_bytes, &path_query, &grove_version).map_err(|e| {
                WillowError::ProofVerificationFailed(format!(
                    "GroveDB proof verification failed: {}",
                    e
                ))
            })?;

        let computed_root = hex::encode(&computed_root_bytes);

        // Compare against current consensus app_hash from /block_results
        let consensus_root = hex::encode(light_client.fetch_current_app_hash().await?);


        // Compare roots
        if computed_root != consensus_root {
            return Err(WillowError::ProofVerificationFailed(format!(
                "Root hash mismatch: computed {} vs consensus {}",
                computed_root, consensus_root
            )));
        }

        Ok(computed_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ensure_authenticated() {
        let client = WillowClient::new("http://localhost:3031").await.unwrap();
        let data_ops = client.data();

        // Should fail when not authenticated
        let result = data_ops.get("subgrove", "key").await;
        assert!(matches!(result, Err(WillowError::NotAuthenticated)));
    }
}
