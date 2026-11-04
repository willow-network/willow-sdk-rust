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
use crate::signed_messages::{self, GrantSubgroveKeyTx, RevokeSubgroveKeyTx, RotateSubgroveKeyTx};
use crate::types::ApiResponse;
use crate::WillowClient;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use willow_types::consensus::transactions::Transaction;

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

/// An encrypted key grant for a subgrove: the chain's own type, so a grant signs and encodes
/// exactly as the node reads it.
pub use willow_types::storage::EncryptedKeyGrant;

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
    pub async fn get_my_key_grant(&self, subgrove_id: &str) -> Result<EncryptedKeyGrant> {
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
    pub async fn list_key_grantees(&self, subgrove_id: &str) -> Result<Vec<String>> {
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
    /// Grants the specified DID access to the subgrove's encryption key. Signed over
    /// [`signed_messages::grant_subgrove_key`], which binds every field of the grant and `nonce`.
    pub async fn grant_subgrove_key(
        &self,
        subgrove_id: &str,
        grant: EncryptedKeyGrant,
        sender_did: &str,
        signing_key: &SigningKey,
        public_key_id: &str,
        nonce: u64,
    ) -> Result<String> {
        let consensus = self.client.require_consensus("grant_subgrove_key")?;
        let mut tx = GrantSubgroveKeyTx {
            subgrove_id: subgrove_id.to_string(),
            encrypted_key_grant: grant,
            sender_did: sender_did.to_string(),
            signature: vec![],
            public_key_id: public_key_id.to_string(),
            nonce,
        };
        let message = signed_messages::grant_subgrove_key(&tx)?;
        tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
        consensus
            .broadcast(&Transaction::GrantSubgroveKey(tx))
            .await
    }

    /// Submit a RevokeSubgroveKey transaction via consensus.
    ///
    /// Revokes the specified DID's access to the subgrove's encryption key. Signed over
    /// [`signed_messages::revoke_subgrove_key`].
    pub async fn revoke_subgrove_key(
        &self,
        subgrove_id: &str,
        revokee_did: &str,
        sender_did: &str,
        signing_key: &SigningKey,
        public_key_id: &str,
        nonce: u64,
    ) -> Result<String> {
        let consensus = self.client.require_consensus("revoke_subgrove_key")?;
        let mut tx = RevokeSubgroveKeyTx {
            subgrove_id: subgrove_id.to_string(),
            revokee_did: revokee_did.to_string(),
            sender_did: sender_did.to_string(),
            signature: vec![],
            public_key_id: public_key_id.to_string(),
            nonce,
        };
        let message = signed_messages::revoke_subgrove_key(&tx)?;
        tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
        consensus
            .broadcast(&Transaction::RevokeSubgroveKey(tx))
            .await
    }

    /// Submit a RotateSubgroveKey transaction via consensus.
    ///
    /// Rotates the subgrove encryption key to a new epoch with new grants. Signed over
    /// [`signed_messages::rotate_subgrove_key`], which binds every grant, their count and order,
    /// and `nonce`.
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
        let consensus = self.client.require_consensus("rotate_subgrove_key")?;
        let mut tx = RotateSubgroveKeyTx {
            subgrove_id: subgrove_id.to_string(),
            new_epoch,
            new_grants,
            sender_did: sender_did.to_string(),
            signature: vec![],
            public_key_id: public_key_id.to_string(),
            nonce,
        };
        let message = signed_messages::rotate_subgrove_key(&tx)?;
        tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
        consensus
            .broadcast(&Transaction::RotateSubgroveKey(tx))
            .await
    }
}
