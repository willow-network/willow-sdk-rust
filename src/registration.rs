//! App and subgrove query operations.
//!
//! This module provides read-only access to app and subgrove registrations.
//! Creating new apps and subgroves requires submitting transactions through
//! the consensus layer.
//!
//! # Example
//!
//! ```rust,ignore
//! use willow_sdk::WillowClient;
//!
//! let client = WillowClient::new("http://localhost:3031").await?;
//!
//! // List all apps
//! let apps = client.registration().list_apps().await?;
//!
//! // Get a specific app
//! let app = client.registration().get_app("my_app").await?;
//!
//! // List subgroves for an app
//! let subgroves = client.registration().list_subgroves("my_app").await?;
//! ```

use crate::client::WillowClient;
use crate::errors::{Result, WillowError};
use crate::types::{ApiResponse, AppRegistration, DidPermissions, SubgroveRegistration};

/// Operations for querying app and subgrove registrations.
pub struct RegistrationOperations {
    client: WillowClient,
}

impl RegistrationOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Lists all registered apps.
    ///
    /// If authenticated, returns apps the caller has access to.
    /// If unauthenticated, returns only public apps.
    pub async fn list_apps(&self) -> Result<Vec<AppRegistration>> {
        let authenticated = self.client.has_identity();

        let response: ApiResponse<Vec<AppRegistration>> = self
            .client
            .request("GET", "/apps", None::<&()>, authenticated)
            .await?;

        Ok(response.data.unwrap_or_default())
    }

    /// Gets a specific app by ID.
    pub async fn get_app(&self, app_id: &str) -> Result<AppRegistration> {
        let response: ApiResponse<AppRegistration> = self
            .client
            .request(
                "GET",
                &format!("/apps/{}", app_id),
                None::<&()>,
                false, // Public endpoint
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("App not found: {}", app_id)))
    }

    /// Lists subgroves for an app.
    ///
    /// If authenticated, returns subgroves the caller has access to.
    /// If unauthenticated, returns only public subgroves.
    pub async fn list_subgroves(&self, app_id: &str) -> Result<Vec<SubgroveRegistration>> {
        let authenticated = self.client.has_identity();

        let response: ApiResponse<Vec<SubgroveRegistration>> = self
            .client
            .request(
                "GET",
                &format!("/apps/{}/subgroves", app_id),
                None::<&()>,
                authenticated,
            )
            .await?;

        Ok(response.data.unwrap_or_default())
    }

    /// Gets a specific subgrove by ID.
    pub async fn get_subgrove(
        &self,
        app_id: &str,
        subgrove_id: &str,
    ) -> Result<SubgroveRegistration> {
        // First list all subgroves and find the specific one
        let subgroves = self.list_subgroves(app_id).await?;

        subgroves
            .into_iter()
            .find(|s| s.subgrove_id == subgrove_id)
            .ok_or_else(|| {
                WillowError::NotFound(format!("Subgrove not found: {}/{}", app_id, subgrove_id))
            })
    }

    /// Gets the permissions for a DID.
    ///
    /// Returns information about apps and subgroves the DID has access to.
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
