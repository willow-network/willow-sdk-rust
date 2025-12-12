//! Validator query operations.
//!
//! This module provides access to validator information including
//! stake amounts, commission rates, and status.
//!
//! # Example
//!
//! ```rust,ignore
//! use willow_sdk::WillowClient;
//!
//! let client = WillowClient::new("http://localhost:3031").await?;
//!
//! // List all validators
//! let validators = client.validators().list().await?;
//! for v in validators {
//!     println!("{}: {} staked", v.validator_did, v.stake_amount);
//! }
//!
//! // Get specific validator
//! let validator = client.validators().get("did:willow:validator123").await?;
//! ```

use crate::client::WillowClient;
use crate::errors::{WillowError, Result};
use crate::types::{ApiResponse, ValidatorInfo};

/// Operations for querying validator information.
pub struct ValidatorOperations {
    client: WillowClient,
}

impl ValidatorOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Lists all validators.
    ///
    /// Returns validators in the active set and those unbonding.
    pub async fn list(&self) -> Result<Vec<ValidatorInfo>> {
        let response: ApiResponse<Vec<ValidatorInfo>> = self
            .client
            .request("GET", "/validators", None::<&()>, false)
            .await?;

        Ok(response.data.unwrap_or_default())
    }

    /// Gets information about a specific validator.
    pub async fn get(&self, validator_did: &str) -> Result<ValidatorInfo> {
        let response: ApiResponse<ValidatorInfo> = self
            .client
            .request(
                "GET",
                &format!("/validators/{}", validator_did),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("Validator not found: {}", validator_did)))
    }

    /// Gets the total staked amount across all validators.
    pub async fn get_total_staked(&self) -> Result<u128> {
        let validators = self.list().await?;
        Ok(validators.iter().map(|v| v.stake_amount).sum())
    }

    /// Gets the number of active validators.
    pub async fn get_active_count(&self) -> Result<usize> {
        let validators = self.list().await?;
        Ok(validators
            .iter()
            .filter(|v| v.status == crate::types::ValidatorStatus::Active)
            .count())
    }
}
