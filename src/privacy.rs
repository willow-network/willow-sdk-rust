//! Privacy operations for private subgroves.
//!
//! This module provides client-side operations for managing private subgroves:
//!
//! - **Key grant management** — grant, revoke, and rotate encryption keys
//! - **Key grant queries** — retrieve grants and proofs via the REST API
//!
//! # Example
//!
//! ```rust,no_run
//! use willow_sdk::WillowClient;
//! use willow_sdk::privacy::{PrivacyConfig, CommitmentFrequency};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = WillowClient::new("http://localhost:3031").await?;
//!
//! // Register a private subgrove
//! let privacy = PrivacyConfig {
//!     allowed_indexers: Some(vec!["did:willow:my-indexer".to_string()]),
//!     commitment_frequency: CommitmentFrequency::EveryNBlocks(10),
//! };
//! # Ok(())
//! # }
//! ```

use crate::errors::{Result, WillowError};
use crate::types::ApiResponse;
use crate::WillowClient;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

/// Privacy configuration for a private subgrove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Optional whitelist of indexer DIDs allowed to index this subgrove.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_indexers: Option<Vec<String>>,
    /// How often the provider must commit state roots to consensus.
    pub commitment_frequency: CommitmentFrequency,
}

/// How often the provider must publish state root commitments on-chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CommitmentFrequency {
    /// Commit after every write/block update.
    EveryUpdate,
    /// Commit every N blocks processed.
    EveryNBlocks(u64),
    /// Commit at least every N seconds.
    EveryNSeconds(u64),
    /// No on-chain commitments.
    Never,
}

/// An encrypted key grant for a subgrove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyGrant {
    pub grantee_did: String,
    pub key_epoch: u32,
    pub grantee_public_key_id: String,
    pub ephemeral_public_key: Vec<u8>,
    pub encrypted_key: Vec<u8>,
    pub granted_by: String,
    pub granted_at: u64,
}

/// Privacy-related operations for private subgroves.
pub struct PrivacyOperations {
    client: WillowClient,
}

impl PrivacyOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Get the encryption key grant for the authenticated DID.
    ///
    /// Returns the encrypted key grant that allows this DID to decrypt
    /// the subgrove's data.
    pub async fn get_my_key_grant(
        &self,
        subgrove_id: &str,
    ) -> Result<EncryptedKeyGrant> {
        let did = self
            .client
            .get_did()
            .ok_or_else(|| WillowError::Authentication("Identity not set".into()))?;

        let response: ApiResponse<EncryptedKeyGrant> = self
            .client
            .request(
                "GET",
                &format!("/key-grants/{}/{}", subgrove_id, did),
                None::<&()>,
                true,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound("Key grant not found".into()))
    }

    /// List all grantee DIDs for a subgrove.
    ///
    /// Only the subgrove owner or admin can call this.
    pub async fn list_key_grantees(
        &self,
        subgrove_id: &str,
    ) -> Result<Vec<String>> {
        let response: ApiResponse<Vec<String>> = self
            .client
            .request(
                "GET",
                &format!("/key-grants/{}", subgrove_id),
                None::<&()>,
                true,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound("No grantees found".into()))
    }

    /// Get the GroveDB Merkle proof for a key grant.
    ///
    /// Public endpoint — proofs are non-sensitive.
    pub async fn get_key_grant_proof(
        &self,
        subgrove_id: &str,
        did: &str,
    ) -> Result<serde_json::Value> {
        let response: ApiResponse<serde_json::Value> = self
            .client
            .request(
                "GET",
                &format!("/proof/key-grant/{}/{}", subgrove_id, did),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound("Proof not found".into()))
    }

    /// Submit a GrantSubgroveKey transaction via consensus.
    ///
    /// Grants the specified DID access to the subgrove's encryption key.
    pub async fn grant_subgrove_key(
        &self,
        subgrove_id: &str,
        grant: EncryptedKeyGrant,
        sender_did: &str,
        signing_key: &SigningKey,
        public_key_id: &str,
        nonce: u64,
    ) -> Result<String> {
        let message = format!(
            "GrantSubgroveKey:{}:{}:{}:{}",
            subgrove_id, grant.grantee_did, sender_did, nonce
        );

        let signature = signing_key.sign(message.as_bytes());

        let tx = serde_json::json!({
            "GrantSubgroveKey": {
                "subgrove_id": subgrove_id,
                "encrypted_key_grant": grant,
                "sender_did": sender_did,
                "signature": signature.to_bytes().to_vec(),
                "public_key_id": public_key_id,
                "nonce": nonce,
            }
        });

        self.client
            .consensus()
            .submit_raw_transaction(tx)
            .await
    }

    /// Submit a RevokeSubgroveKey transaction via consensus.
    ///
    /// Revokes the specified DID's access to the subgrove's encryption key.
    pub async fn revoke_subgrove_key(
        &self,
        subgrove_id: &str,
        revokee_did: &str,
        sender_did: &str,
        signing_key: &SigningKey,
        public_key_id: &str,
        nonce: u64,
    ) -> Result<String> {
        let message = format!(
            "RevokeSubgroveKey:{}:{}:{}:{}",
            subgrove_id, revokee_did, sender_did, nonce
        );

        let signature = signing_key.sign(message.as_bytes());

        let tx = serde_json::json!({
            "RevokeSubgroveKey": {
                "subgrove_id": subgrove_id,
                "revokee_did": revokee_did,
                "sender_did": sender_did,
                "signature": signature.to_bytes().to_vec(),
                "public_key_id": public_key_id,
                "nonce": nonce,
            }
        });

        self.client
            .consensus()
            .submit_raw_transaction(tx)
            .await
    }

    /// Submit a RotateSubgroveKey transaction via consensus.
    ///
    /// Rotates the subgrove encryption key to a new epoch with new grants.
    pub async fn rotate_subgrove_key(
        &self,
        subgrove_id: &str,
        new_epoch: u32,
        new_grants: Vec<EncryptedKeyGrant>,
        sender_did: &str,
        signing_key: &SigningKey,
        public_key_id: &str,
        nonce: u64,
    ) -> Result<String> {
        let message = format!(
            "RotateSubgroveKey:{}:{}:{}:{}",
            subgrove_id, new_epoch, sender_did, nonce
        );

        let signature = signing_key.sign(message.as_bytes());

        let tx = serde_json::json!({
            "RotateSubgroveKey": {
                "subgrove_id": subgrove_id,
                "new_epoch": new_epoch,
                "new_grants": new_grants,
                "sender_did": sender_did,
                "signature": signature.to_bytes().to_vec(),
                "public_key_id": public_key_id,
                "nonce": nonce,
            }
        });

        self.client
            .consensus()
            .submit_raw_transaction(tx)
            .await
    }
}
