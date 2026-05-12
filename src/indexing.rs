//! Indexing and GraphQL operations for querying blockchain data.
//!
//! This module provides access to indexed blockchain data through GraphQL
//! queries and subgrove management.
//!
//! # Example
//!
//! ```rust,ignore
//! use willow_sdk::WillowClient;
//!
//! let client = WillowClient::new("http://localhost:3031").await?;
//!
//! // Query a subgrove using GraphQL
//! let result = client.indexing()
//!     .graphql_query("uniswap-v3", r#"
//!         query {
//!             swaps(first: 10) {
//!                 id
//!                 amount0
//!                 amount1
//!             }
//!         }
//!     "#, None)
//!     .await?;
//!
//! // List available subgroves
//! let subgroves = client.indexing().list_subgroves().await?;
//! ```

use crate::client::WillowClient;
use crate::errors::{Result, WillowError};
use crate::indexers::{QuerySource, RoutedQueryResult, ServedBy};
use crate::types::{
    ApiResponse, GraphQLRequest, GraphQLResponse, IndexerInfo, SubgroveIndexingStatus,
    SubgroveInfo, VerificationStats,
};

/// Returned when `source: Validator` is requested but the validator has no
/// data for the subgrove (VerifyOnly retention, pruned, or not indexed).
#[derive(Debug, Clone)]
pub struct ValidatorHasNoData {
    pub subgrove_id: String,
    pub reason: String,
}

/// Returned when `source: Indexer` is requested but either no indexer serves
/// the subgrove or every candidate failed.
#[derive(Debug, Clone)]
pub struct NoIndexersReachable {
    pub subgrove_id: String,
    pub details: String,
}

/// Operations for interacting with indexed blockchain data.
pub struct IndexingOperations {
    client: WillowClient,
}

impl IndexingOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Executes a GraphQL query against an indexed subgrove.
    ///
    /// Legacy signature: always targets [`WillowClient::indexer_base_url`] —
    /// the explicit `indexer_url` override if set, else the validator. For
    /// source-routed queries (auto-discovery, explicit validator fallback,
    /// etc.) use [`Self::graphql_query_with_source`].
    pub async fn graphql_query(
        &self,
        subgrove_id: &str,
        query: &str,
        variables: Option<serde_json::Value>,
    ) -> Result<GraphQLResponse> {
        self.graphql_query_legacy(subgrove_id, query, variables)
            .await
    }

    /// Executes a GraphQL query with explicit source selection.
    ///
    /// The `source` argument makes the trust model part of the API: callers
    /// declare whether they want consensus-verified chain-tip data
    /// ([`QuerySource::Validator`]), historical/analytics data
    /// ([`QuerySource::Indexer`]), or "best effort with fallback"
    /// ([`QuerySource::Auto`], usually what you want).
    ///
    /// The returned [`RoutedQueryResult`] tells the caller which backend
    /// actually served the query so UIs can surface it to users.
    pub async fn graphql_query_with_source(
        &self,
        subgrove_id: &str,
        query: &str,
        variables: Option<serde_json::Value>,
        source: QuerySource,
    ) -> Result<RoutedQueryResult<GraphQLResponse>> {
        let request = GraphQLRequest {
            query: query.to_string(),
            variables,
        };
        self.route("graphql", subgrove_id, &request, source).await
    }

    /// Original (pre-source-routing) GraphQL implementation, preserved so
    /// the legacy `graphql_query(..)` method's semantics don't change.
    async fn graphql_query_legacy(
        &self,
        subgrove_id: &str,
        query: &str,
        variables: Option<serde_json::Value>,
    ) -> Result<GraphQLResponse> {
        let request = GraphQLRequest {
            query: query.to_string(),
            variables,
        };

        let base = self.client.indexer_base_url();
        let path = format!("graphql/{}", subgrove_id);
        let url = base
            .join(&path)
            .map_err(|e| WillowError::Config(format!("Invalid URL: {}", e)))?;

        let mut req_builder = self.client.http_client.post(url).json(&request);
        if let Some(headers) = self.client.sign_request("POST", &format!("/{}", path)) {
            for (key, value) in headers {
                req_builder = req_builder.header(&key, &value);
            }
        }

        let http_resp = req_builder.send().await?;
        let status = http_resp.status();
        let text = http_resp.text().await?;

        if status.is_success() {
            if let Ok(direct) = serde_json::from_str::<GraphQLResponse>(&text) {
                return Ok(direct);
            }
            let api: ApiResponse<GraphQLResponse> =
                serde_json::from_str(&text).map_err(WillowError::Serialization)?;
            api.data
                .ok_or_else(|| WillowError::Custom("No data in GraphQL response".to_string()))
        } else {
            Err(WillowError::Http {
                status: status.as_u16(),
                message: text,
            })
        }
    }

    /// Shared source-routing helper for both `/graphql/:sg` and `/sql/:sg`.
    pub(crate) async fn route<B, T>(
        &self,
        path_prefix: &'static str,
        subgrove_id: &str,
        body: &B,
        source: QuerySource,
    ) -> Result<RoutedQueryResult<T>>
    where
        B: serde::Serialize + ?Sized,
        T: serde::de::DeserializeOwned,
    {
        let path = format!("{}/{}", path_prefix, subgrove_id);

        match source {
            QuerySource::Validator => {
                let result: T = self.call_validator(&path, body).await?;
                Ok(RoutedQueryResult {
                    result,
                    source: ServedBy::Validator,
                    indexer_did: None,
                    fallback: false,
                })
            }
            QuerySource::Indexer => {
                let candidates = self.client.indexers().for_subgrove(subgrove_id).await?;
                if candidates.is_empty() {
                    return Err(WillowError::Custom(format!(
                        "No indexer serves subgrove {}",
                        subgrove_id
                    )));
                }
                let mut errs: Vec<String> = Vec::new();
                for info in &candidates {
                    match self.call_indexer::<B, T>(info, &path, body).await {
                        Ok(result) => {
                            return Ok(RoutedQueryResult {
                                result,
                                source: ServedBy::Indexer,
                                indexer_did: Some(info.indexer_did.clone()),
                                fallback: false,
                            });
                        }
                        Err(e) => {
                            if let WillowError::Http { status, .. } = &e {
                                if *status >= 500 {
                                    self.client.indexers().evict(&info.indexer_did);
                                }
                            }
                            errs.push(format!("{}: {}", info.indexer_did, e));
                        }
                    }
                }
                Err(WillowError::Custom(format!(
                    "No indexer could serve subgrove {}: {}",
                    subgrove_id,
                    errs.join("; ")
                )))
            }
            QuerySource::Auto => {
                let candidates = self
                    .client
                    .indexers()
                    .for_subgrove(subgrove_id)
                    .await
                    .unwrap_or_default();
                let had_indexer_candidates = !candidates.is_empty();
                for info in &candidates {
                    match self.call_indexer::<B, T>(info, &path, body).await {
                        Ok(result) => {
                            return Ok(RoutedQueryResult {
                                result,
                                source: ServedBy::Indexer,
                                indexer_did: Some(info.indexer_did.clone()),
                                fallback: false,
                            });
                        }
                        Err(e) => {
                            if let WillowError::Http { status, .. } = &e {
                                if *status >= 500 {
                                    self.client.indexers().evict(&info.indexer_did);
                                }
                            }
                        }
                    }
                }
                let result: T = self.call_validator(&path, body).await?;
                Ok(RoutedQueryResult {
                    result,
                    source: ServedBy::Validator,
                    indexer_did: None,
                    fallback: had_indexer_candidates,
                })
            }
        }
    }

    async fn call_validator<B, T>(&self, path: &str, body: &B) -> Result<T>
    where
        B: serde::Serialize + ?Sized,
        T: serde::de::DeserializeOwned,
    {
        let url = self
            .client
            .validator_base_url()
            .join(path)
            .map_err(|e| WillowError::Config(format!("Invalid URL: {}", e)))?;

        let mut req = self.client.http_client.post(url).json(body);
        if let Some(headers) = self.client.sign_request("POST", &format!("/{}", path)) {
            for (k, v) in headers {
                req = req.header(&k, &v);
            }
        }

        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(WillowError::Http {
                status: status.as_u16(),
                message: text,
            });
        }
        // Try raw T first (indexer-shaped), fall back to ApiResponse<T> wrapper.
        if let Ok(direct) = serde_json::from_str::<T>(&text) {
            return Ok(direct);
        }
        let api: ApiResponse<T> =
            serde_json::from_str(&text).map_err(WillowError::Serialization)?;
        api.data
            .ok_or_else(|| WillowError::Custom("empty data in response".to_string()))
    }

    async fn call_indexer<B, T>(&self, info: &IndexerInfo, path: &str, body: &B) -> Result<T>
    where
        B: serde::Serialize + ?Sized,
        T: serde::de::DeserializeOwned,
    {
        let endpoint = info.effective_query_endpoint().trim_end_matches('/');
        let url_str = format!("{}/{}", endpoint, path);
        let url = url::Url::parse(&url_str)
            .map_err(|e| WillowError::Config(format!("Invalid indexer URL {}: {}", url_str, e)))?;

        let mut req = self.client.http_client.post(url).json(body);
        if let Some(headers) = self.client.sign_request("POST", &format!("/{}", path)) {
            for (k, v) in headers {
                req = req.header(&k, &v);
            }
        }

        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(WillowError::Http {
                status: status.as_u16(),
                message: text,
            });
        }
        if let Ok(direct) = serde_json::from_str::<T>(&text) {
            return Ok(direct);
        }
        let api: ApiResponse<T> =
            serde_json::from_str(&text).map_err(WillowError::Serialization)?;
        api.data
            .ok_or_else(|| WillowError::Custom("empty data in response".to_string()))
    }

    /// Lists all available subgroves.
    pub async fn list_subgroves(&self) -> Result<Vec<SubgroveInfo>> {
        let response: ApiResponse<Vec<SubgroveInfo>> = self
            .client
            .request("GET", "/subgroves", None::<&()>, false)
            .await?;

        Ok(response.data.unwrap_or_default())
    }

    /// Gets information about a specific subgrove.
    pub async fn get_subgrove(&self, subgrove_id: &str) -> Result<SubgroveInfo> {
        let response: ApiResponse<SubgroveInfo> = self
            .client
            .request(
                "GET",
                &format!("/subgroves/{}", subgrove_id),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("Subgrove not found: {}", subgrove_id)))
    }

    /// Gets the indexing status of a subgrove.
    pub async fn get_subgrove_status(&self, subgrove_id: &str) -> Result<SubgroveIndexingStatus> {
        let response: ApiResponse<SubgroveIndexingStatus> = self
            .client
            .request(
                "GET",
                &format!("/subgroves/{}/status", subgrove_id),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("Subgrove not found: {}", subgrove_id)))
    }

    /// Lists all registered indexers.
    pub async fn list_indexers(&self) -> Result<Vec<IndexerInfo>> {
        let response: ApiResponse<Vec<IndexerInfo>> = self
            .client
            .request("GET", "/indexers", None::<&()>, false)
            .await?;

        Ok(response.data.unwrap_or_default())
    }

    /// Gets information about a specific indexer.
    pub async fn get_indexer(&self, indexer_did: &str) -> Result<IndexerInfo> {
        let response: ApiResponse<IndexerInfo> = self
            .client
            .request(
                "GET",
                &format!("/indexers/{}", indexer_did),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("Indexer not found: {}", indexer_did)))
    }

    /// Gets verification statistics for the indexing system.
    pub async fn get_verification_stats(&self) -> Result<VerificationStats> {
        let response: ApiResponse<VerificationStats> = self
            .client
            .request("GET", "/verification/stats", None::<&()>, false)
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::Custom("No verification stats available".to_string()))
    }
}
