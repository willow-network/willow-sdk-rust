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
use crate::types::{
    ApiResponse, GraphQLRequest, GraphQLResponse, IndexerInfo, SubgroveIndexingStatus,
    SubgroveInfo, VerificationStats,
};

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
    /// When an `indexer_url` is configured on the client, the query is routed
    /// to the indexer node. Otherwise it falls back to the validator API.
    ///
    /// # Arguments
    ///
    /// * `subgrove_id` - The subgrove to query
    /// * `query` - The GraphQL query string
    /// * `variables` - Optional query variables
    ///
    /// # Returns
    ///
    /// The query result with optional cryptographic proof.
    pub async fn graphql_query(
        &self,
        subgrove_id: &str,
        query: &str,
        variables: Option<serde_json::Value>,
    ) -> Result<GraphQLResponse> {
        let request = GraphQLRequest {
            query: query.to_string(),
            variables,
        };

        // Route to indexer node when configured, otherwise use the validator API
        let base = self.client.indexer_base_url();
        let url = base
            .join(&format!("graphql/{}", subgrove_id))
            .map_err(|e| WillowError::Config(format!("Invalid URL: {}", e)))?;

        let http_resp = self
            .client
            .http_client
            .post(url)
            .json(&request)
            .send()
            .await?;

        let status = http_resp.status();
        let text = http_resp.text().await?;

        if status.is_success() {
            // Try direct GraphQL response first (indexer returns this format)
            if let Ok(direct) = serde_json::from_str::<GraphQLResponse>(&text) {
                return Ok(direct);
            }
            // Fall back to ApiResponse wrapper (validator returns this format)
            let api: ApiResponse<GraphQLResponse> = serde_json::from_str(&text)
                .map_err(|e| WillowError::Serialization(e))?;
            api.data
                .ok_or_else(|| WillowError::Custom("No data in GraphQL response".to_string()))
        } else {
            Err(WillowError::Http {
                status: status.as_u16(),
                message: text,
            })
        }
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
