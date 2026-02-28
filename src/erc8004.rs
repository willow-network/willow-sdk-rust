//! ERC-8004 (Trustless Agents) integration for Willow.
//!
//! Provides helper functions to link Ethereum addresses to Willow DIDs and
//! register agents on the ERC-8004 registry.

use crate::errors::{Result, WillowError};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Transaction to link an ETH address to a Willow DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkEthAddressTx {
    pub did: String,
    pub eth_address: [u8; 20],
    pub public_key_id: String,
    pub signature: Vec<u8>,
    pub nonce: u64,
}

/// Transaction to record an ERC-8004 agent registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterErc8004AgentTx {
    pub did: String,
    pub chain_id: u64,
    pub registry_address: [u8; 20],
    pub agent_id: u64,
    pub agent_uri: String,
    pub signature: Vec<u8>,
    pub public_key_id: String,
    pub nonce: u64,
}

/// ERC-8004 agent registration JSON returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistrationJson {
    #[serde(rename = "type")]
    pub reg_type: String,
    pub name: String,
    pub description: String,
    pub services: Vec<AgentService>,
    pub x402_support: bool,
    pub active: bool,
    pub registrations: Vec<AgentChainRegistration>,
    pub supported_trust: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<AgentReputationSummary>,
}

/// Summary of an agent's reputation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReputationSummary {
    pub score: u32,
    pub tier: String,
    pub checkpoint_success_rate: f64,
    pub verification_accuracy: f64,
    pub active_days: u32,
    pub last_updated: u64,
}

/// Reputation attestation with GroveDB Merkle proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationAttestation {
    pub did: String,
    pub score: u32,
    pub tier: String,
    pub metrics: serde_json::Value,
    pub proof: String,
    pub block_height: u64,
    pub last_updated: u64,
}

/// A single reputation history event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationHistoryEvent {
    pub event_type: String,
    pub score_delta: i32,
    pub new_score: u32,
    pub block_height: u64,
    pub timestamp: u64,
    pub reference: Option<String>,
}

/// ERC-8004 formatted reputation history response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationHistoryResponse {
    pub did: String,
    pub events: Vec<ReputationHistoryEvent>,
    pub total_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentService {
    pub name: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentChainRegistration {
    pub chain_id: u64,
    pub registry: String,
    pub agent_id: u64,
}

/// Stored ERC-8004 registration details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc8004Registration {
    pub chain_id: u64,
    pub registry_address: [u8; 20],
    pub agent_id: u64,
    pub agent_uri: String,
    pub registered_at: u64,
}

// ── Validation Registry types ─────────────────────────────────────────

/// A single ERC-8004 validation record (checkpoint mapped to validation format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc8004ValidationRecord {
    pub request_hash: String,
    pub subgrove_id: String,
    pub block_range: (u64, u64),
    pub state_root: String,
    pub response: u32,
    pub status: String,
    pub tee_verified: bool,
    pub tee_type: Option<String>,
    pub submitted_at_block: u64,
    pub challenge_deadline: Option<u64>,
    pub tag: String,
}

/// Response for the validation-status endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc8004ValidationStatusResponse {
    pub did: String,
    pub validations: Vec<Erc8004ValidationRecord>,
    pub total: usize,
}

/// Breakdown of validation statuses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStatusBreakdown {
    pub trusted: u64,
    pub pending_challenge: u64,
    pub tee_attested: u64,
    pub disputed: u64,
    pub invalidated: u64,
}

/// Statistics about an indexer's dispute participation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeStats {
    pub disputes_won_as_defendant: u64,
    pub disputes_lost_as_defendant: u64,
    pub disputes_won_as_challenger: u64,
    pub disputes_lost_as_challenger: u64,
}

/// Aggregated validation summary in ERC-8004 format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc8004ValidationSummary {
    pub did: String,
    pub count: usize,
    pub average_response: f64,
    pub status_breakdown: ValidationStatusBreakdown,
    pub dispute_stats: DisputeStats,
}

/// ERC-8004 client for interacting with agent identity endpoints.
pub struct Erc8004Client {
    api_url: String,
    http: Client,
}

impl Erc8004Client {
    pub fn new(api_url: &str) -> Self {
        Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            http: Client::new(),
        }
    }

    /// Fetch the ERC-8004 agent registration JSON for a DID.
    pub async fn get_agent_registration(&self, did: &str) -> Result<AgentRegistrationJson> {
        let url = format!("{}/agent/{}/registration.json", self.api_url, did);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WillowError::Network(format!("Request failed: {}", e)))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WillowError::Network(format!("Failed to parse response: {}", e)))?;

        if let Some(data) = body.get("data") {
            serde_json::from_value(data.clone())
                .map_err(|e| WillowError::Network(format!("Failed to parse registration: {}", e)))
        } else {
            Err(WillowError::Network(
                body.get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Unknown error")
                    .to_string(),
            ))
        }
    }

    /// Get the ETH address linked to a DID.
    pub async fn get_eth_address(&self, did: &str) -> Result<Option<String>> {
        let url = format!("{}/did/{}/eth-address", self.api_url, did);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WillowError::Network(format!("Request failed: {}", e)))?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WillowError::Network(format!("Failed to parse response: {}", e)))?;

        Ok(body
            .get("data")
            .and_then(|d| d.get("eth_address"))
            .and_then(|a| a.as_str())
            .map(|s| s.to_string()))
    }

    /// Get the DID linked to an ETH address.
    pub async fn get_did_for_eth(&self, eth_address: &str) -> Result<Option<String>> {
        let url = format!("{}/eth-address/{}/did", self.api_url, eth_address);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WillowError::Network(format!("Request failed: {}", e)))?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WillowError::Network(format!("Failed to parse response: {}", e)))?;

        Ok(body
            .get("data")
            .and_then(|d| d.get("did"))
            .and_then(|a| a.as_str())
            .map(|s| s.to_string()))
    }

    /// Get the stored ERC-8004 registration details for a DID.
    pub async fn get_erc8004_details(&self, did: &str) -> Result<Option<Erc8004Registration>> {
        let url = format!("{}/did/{}/erc8004", self.api_url, did);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WillowError::Network(format!("Request failed: {}", e)))?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WillowError::Network(format!("Failed to parse response: {}", e)))?;

        if let Some(data) = body.get("data") {
            let reg = serde_json::from_value(data.clone())
                .map_err(|e| WillowError::Network(format!("Failed to parse registration: {}", e)))?;
            Ok(Some(reg))
        } else {
            Ok(None)
        }
    }

    /// Fetch reputation attestation with GroveDB Merkle proof for a DID.
    pub async fn get_reputation_attestation(&self, did: &str) -> Result<ReputationAttestation> {
        let url = format!("{}/agent/{}/reputation-attestation", self.api_url, did);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WillowError::Network(format!("Request failed: {}", e)))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WillowError::Network(format!("Failed to parse response: {}", e)))?;

        if let Some(data) = body.get("data") {
            serde_json::from_value(data.clone())
                .map_err(|e| WillowError::Network(format!("Failed to parse attestation: {}", e)))
        } else {
            Err(WillowError::Network(
                body.get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Unknown error")
                    .to_string(),
            ))
        }
    }

    /// Fetch ERC-8004 formatted reputation history for a DID.
    pub async fn get_reputation_history(
        &self,
        did: &str,
        limit: Option<usize>,
    ) -> Result<ReputationHistoryResponse> {
        let mut url = format!("{}/agent/{}/reputation-history", self.api_url, did);
        if let Some(limit) = limit {
            url = format!("{}?limit={}", url, limit);
        }
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WillowError::Network(format!("Request failed: {}", e)))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WillowError::Network(format!("Failed to parse response: {}", e)))?;

        if let Some(data) = body.get("data") {
            serde_json::from_value(data.clone())
                .map_err(|e| WillowError::Network(format!("Failed to parse history: {}", e)))
        } else {
            Err(WillowError::Network(
                body.get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Unknown error")
                    .to_string(),
            ))
        }
    }

    /// Fetch ERC-8004 validation status (checkpoint validations) for a DID.
    pub async fn get_validation_status(
        &self,
        did: &str,
        limit: Option<usize>,
        subgrove_id: Option<&str>,
    ) -> Result<Erc8004ValidationStatusResponse> {
        let mut url = format!("{}/agent/{}/validation-status", self.api_url, did);
        let mut params = Vec::new();
        if let Some(limit) = limit {
            params.push(format!("limit={}", limit));
        }
        if let Some(sg) = subgrove_id {
            params.push(format!("subgrove_id={}", sg));
        }
        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WillowError::Network(format!("Request failed: {}", e)))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WillowError::Network(format!("Failed to parse response: {}", e)))?;

        if let Some(data) = body.get("data") {
            serde_json::from_value(data.clone()).map_err(|e| {
                WillowError::Network(format!("Failed to parse validation status: {}", e))
            })
        } else {
            Err(WillowError::Network(
                body.get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Unknown error")
                    .to_string(),
            ))
        }
    }

    /// Fetch aggregated ERC-8004 validation summary for a DID.
    pub async fn get_validation_summary(
        &self,
        did: &str,
        subgrove_id: Option<&str>,
    ) -> Result<Erc8004ValidationSummary> {
        let mut url = format!("{}/agent/{}/validation-summary", self.api_url, did);
        if let Some(sg) = subgrove_id {
            url = format!("{}?subgrove_id={}", url, sg);
        }

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WillowError::Network(format!("Request failed: {}", e)))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| WillowError::Network(format!("Failed to parse response: {}", e)))?;

        if let Some(data) = body.get("data") {
            serde_json::from_value(data.clone()).map_err(|e| {
                WillowError::Network(format!("Failed to parse validation summary: {}", e))
            })
        } else {
            Err(WillowError::Network(
                body.get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Unknown error")
                    .to_string(),
            ))
        }
    }
}
