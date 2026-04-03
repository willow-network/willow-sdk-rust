//! Subgrove query operations.
//!
//! This module provides read-only access to subgrove registrations.
//! Creating new subgroves requires submitting transactions through
//! the consensus layer.
//!
//! # Example
//!
//! ```rust,ignore
//! use willow_sdk::WillowClient;
//!
//! let client = WillowClient::new("http://localhost:3031").await?;
//!
//! // List all subgroves
//! let subgroves = client.registration().list_subgroves().await?;
//!
//! // Get a specific subgrove
//! let subgrove = client.registration().get_subgrove("my_subgrove").await?;
//! ```

use crate::client::WillowClient;
use crate::errors::{Result, WillowError};
use crate::types::{ApiResponse, DidPermissions, SubgroveRegistration};

/// Operations for querying subgrove registrations.
pub struct RegistrationOperations {
    client: WillowClient,
}

impl RegistrationOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Lists all registered subgroves.
    ///
    /// If authenticated, returns subgroves the caller has access to.
    /// If unauthenticated, returns only public subgroves.
    pub async fn list_subgroves(&self) -> Result<Vec<SubgroveRegistration>> {
        let authenticated = self.client.has_identity();

        let response: ApiResponse<Vec<SubgroveRegistration>> = self
            .client
            .request("GET", "/subgroves", None::<&()>, authenticated)
            .await?;

        Ok(response.data.unwrap_or_default())
    }

    /// Gets a specific subgrove by ID.
    pub async fn get_subgrove(
        &self,
        subgrove_id: &str,
    ) -> Result<SubgroveRegistration> {
        let subgroves = self.list_subgroves().await?;

        subgroves
            .into_iter()
            .find(|s| s.subgrove_id == subgrove_id)
            .ok_or_else(|| {
                WillowError::NotFound(format!("Subgrove not found: {}", subgrove_id))
            })
    }

    /// Gets the permissions for a DID.
    ///
    /// Returns information about subgroves the DID has access to.
    pub async fn get_did_permissions(&self, did: &str) -> Result<DidPermissions> {
        let response: ApiResponse<DidPermissions> = self
            .client
            .request(
                "GET",
                &format!("/did/{}/permissions", did),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("DID not found: {}", did)))
    }
}
