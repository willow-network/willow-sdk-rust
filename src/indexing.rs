//! Indexing and GraphQL operations for querying blockchain data.
//!
//! This module provides access to indexed blockchain data through GraphQL
//! queries and subgraph management.
//!
//! # Example
//!
//! ```rust,ignore
//! use willow_sdk::WillowClient;
//!
//! let client = WillowClient::new("http://localhost:3031").await?;
//!
//! // Query a subgraph using GraphQL
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
//! // List available subgraphs
//! let subgraphs = client.indexing().list_subgraphs().await?;
//! ```

use crate::client::WillowClient;
use crate::errors::{WillowError, Result};
use crate::types::{
    ApiResponse, GraphQLRequest, GraphQLResponse, IndexerInfo, SubgraphIndexingStatus,
    SubgraphInfo, VerificationStats,
};

/// Operations for interacting with indexed blockchain data.
pub struct IndexingOperations {
    client: WillowClient,
}

impl IndexingOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Executes a GraphQL query against an indexed subgraph.
    ///
    /// # Arguments
    ///
    /// * `subgraph_id` - The subgraph to query
    /// * `query` - The GraphQL query string
    /// * `variables` - Optional query variables
    ///
    /// # Returns
    ///
    /// The query result with optional cryptographic proof.
    pub async fn graphql_query(
        &self,
        subgraph_id: &str,
        query: &str,
        variables: Option<serde_json::Value>,
    ) -> Result<GraphQLResponse> {
        let request = GraphQLRequest {
            query: query.to_string(),
            variables,
        };

        let response: ApiResponse<GraphQLResponse> = self
            .client
            .request(
                "POST",
                &format!("/graphql/{}", subgraph_id),
                Some(&request),
                false, // GraphQL queries don't require auth
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::Custom("No data in GraphQL response".to_string()))
    }

    /// Lists all available subgraphs.
    pub async fn list_subgraphs(&self) -> Result<Vec<SubgraphInfo>> {
        let response: ApiResponse<Vec<SubgraphInfo>> = self
            .client
            .request("GET", "/subgraphs", None::<&()>, false)
            .await?;

        Ok(response.data.unwrap_or_default())
    }

    /// Gets information about a specific subgraph.
    pub async fn get_subgraph(&self, subgraph_id: &str) -> Result<SubgraphInfo> {
        let response: ApiResponse<SubgraphInfo> = self
            .client
            .request(
                "GET",
                &format!("/subgraphs/{}", subgraph_id),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("Subgraph not found: {}", subgraph_id)))
    }

    /// Gets the indexing status of a subgraph.
    pub async fn get_subgraph_status(&self, subgraph_id: &str) -> Result<SubgraphIndexingStatus> {
        let response: ApiResponse<SubgraphIndexingStatus> = self
            .client
            .request(
                "GET",
                &format!("/subgraphs/{}/status", subgraph_id),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("Subgraph not found: {}", subgraph_id)))
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
