//! Token and balance operations.
//!
//! This module provides access to WILL token information, balances,
//! and fee schedules.
//!
//! # Example
//!
//! ```rust,ignore
//! use willow_sdk::WillowClient;
//!
//! let client = WillowClient::new("http://localhost:3031").await?;
//!
//! // Get token info
//! let info = client.token().get_info().await?;
//! println!("Max supply: {} {}", info.max_supply, info.symbol);
//!
//! // Check balance
//! let balance = client.token().get_balance("did:willow:abc123").await?;
//! println!("Available: {}", balance.available);
//!
//! // Get fee schedule
//! let fees = client.token().get_fee_schedule().await?;
//! ```

use crate::client::WillowClient;
use crate::errors::{Result, WillowError};
use crate::types::{ApiResponse, SubgroveBalanceInfo, BalanceInfo, FeeSchedule, TokenInfo};

/// Operations for token information and balances.
pub struct TokenOperations {
    client: WillowClient,
}

impl TokenOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Gets information about the WILL token.
    pub async fn get_info(&self) -> Result<TokenInfo> {
        let response: ApiResponse<TokenInfo> = self
            .client
            .request("GET", "/token/info", None::<&()>, false)
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::Custom("No token info available".to_string()))
    }

    /// Gets the balance for a DID.
    ///
    /// This is a public endpoint and does not require authentication.
    pub async fn get_balance(&self, did: &str) -> Result<BalanceInfo> {
        let response: ApiResponse<BalanceInfo> = self
            .client
            .request(
                "GET",
                &format!("/token/balance/{}", did),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("Balance not found for: {}", did)))
    }

    /// Gets the balance for a subgrove.
    ///
    /// This is a public endpoint and does not require authentication.
    pub async fn get_subgrove_balance(&self, subgrove_id: &str) -> Result<SubgroveBalanceInfo> {
        let response: ApiResponse<SubgroveBalanceInfo> = self
            .client
            .request(
                "GET",
                &format!("/token/subgrove/balance/{}", subgrove_id),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("Subgrove balance not found for: {}", subgrove_id)))
    }

    /// Gets the current fee schedule.
    ///
    /// Returns storage fees, query fees, and minimum balances.
    pub async fn get_fee_schedule(&self) -> Result<FeeSchedule> {
        let response: ApiResponse<FeeSchedule> = self
            .client
            .request("GET", "/fees/schedule", None::<&()>, false)
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::Custom("No fee schedule available".to_string()))
    }
}
