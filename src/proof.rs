//! Proof verification for Willow query results.
//!
//! This module provides utilities for verifying cryptographic proofs
//! returned by Willow queries. Full proof verification uses GroveDB's
//! lightweight verify-only mode (no RocksDB dependency).
//!
//! Disable with the `no-light-client` feature for minimal dependencies.

use crate::errors::{WillowError, Result};
use serde_json::Value;

#[cfg(not(feature = "no-light-client"))]
use grovedb::{GroveDb, PathQuery, Query};

/// Proof verification functionality.
///
/// With `no-light-client` feature, only basic proof parsing is available.
pub struct ProofVerifier;

impl ProofVerifier {
    /// Verify a query proof and extract the root hash.
    ///
    /// # Arguments
    /// * `proof_hex` - Hex-encoded GroveDB proof from query response
    /// * `documents` - The documents returned in the query (for result verification)
    ///
    /// # Returns
    /// * `Ok(root_hash)` - The computed root hash (hex-encoded) if verification succeeds
    /// * `Err` if there was an error during verification
    ///
    /// Disabled with `no-light-client` feature.
    #[cfg(not(feature = "no-light-client"))]
    pub fn verify_query_proof(proof_hex: &str, _documents: &[Value]) -> Result<String> {
        let proof_bytes = hex::decode(proof_hex).map_err(|e| {
            WillowError::ProofVerificationFailed(format!("Invalid proof hex: {}", e))
        })?;

        if proof_bytes.is_empty() {
            return Err(WillowError::ProofVerificationFailed(
                "Empty proof provided".to_string(),
            ));
        }

        // Use GroveDB's verify_query to extract the root hash
        let empty_path: Vec<Vec<u8>> = vec![];
        let query = Query::new();
        let path_query = PathQuery::new_unsized(empty_path, query);
        let grove_version = grovedb_version::version::GroveVersion::default();

        match GroveDb::verify_query(&proof_bytes, &path_query, &grove_version) {
            Ok((root_hash, _verified_items)) => Ok(hex::encode(root_hash)),
            Err(e) => Err(WillowError::ProofVerificationFailed(format!(
                "GroveDB verification failed: {}",
                e
            ))),
        }
    }

    /// Verify a query proof (stub with no-light-client feature).
    #[cfg(feature = "no-light-client")]
    pub fn verify_query_proof(proof_hex: &str, _documents: &[Value]) -> Result<String> {
        let proof_bytes = hex::decode(proof_hex).map_err(|e| {
            WillowError::ProofVerificationFailed(format!("Invalid proof hex: {}", e))
        })?;

        if proof_bytes.is_empty() {
            return Err(WillowError::ProofVerificationFailed(
                "Empty proof provided".to_string(),
            ));
        }

        Err(WillowError::ProofVerificationFailed(
            "Proof verification disabled with 'no-light-client' feature. \
             Remove this feature to enable verification."
                .to_string(),
        ))
    }

    /// Verify a single item proof and extract root hash.
    #[cfg(not(feature = "no-light-client"))]
    pub fn verify_item_proof(proof_hex: &str, key: &str, _value: &Value) -> Result<String> {
        let proof_bytes = hex::decode(proof_hex).map_err(|e| {
            WillowError::ProofVerificationFailed(format!("Invalid proof hex: {}", e))
        })?;

        if proof_bytes.is_empty() {
            return Err(WillowError::ProofVerificationFailed(
                "Empty proof provided".to_string(),
            ));
        }

        // Construct a single-key query
        let empty_path: Vec<Vec<u8>> = vec![];
        let mut query = Query::new();
        query.insert_key(key.as_bytes().to_vec());
        let path_query = PathQuery::new_unsized(empty_path, query);
        let grove_version = grovedb_version::version::GroveVersion::default();

        match GroveDb::verify_query(&proof_bytes, &path_query, &grove_version) {
            Ok((root_hash, _)) => Ok(hex::encode(root_hash)),
            Err(e) => Err(WillowError::ProofVerificationFailed(format!(
                "Failed to verify proof for key '{}': {}",
                key, e
            ))),
        }
    }

    /// Verify a single item proof (stub with no-light-client feature).
    #[cfg(feature = "no-light-client")]
    pub fn verify_item_proof(proof_hex: &str, _key: &str, _value: &Value) -> Result<String> {
        let proof_bytes = hex::decode(proof_hex).map_err(|e| {
            WillowError::ProofVerificationFailed(format!("Invalid proof hex: {}", e))
        })?;

        if proof_bytes.is_empty() {
            return Err(WillowError::ProofVerificationFailed(
                "Empty proof provided".to_string(),
            ));
        }

        Err(WillowError::ProofVerificationFailed(
            "Proof verification disabled with 'no-light-client' feature.".to_string(),
        ))
    }

    /// Parse proof bytes without verification.
    ///
    /// Always available for proof inspection.
    pub fn parse_proof_hex(proof_hex: &str) -> Result<Vec<u8>> {
        hex::decode(proof_hex)
            .map_err(|e| WillowError::ProofVerificationFailed(format!("Invalid proof hex: {}", e)))
    }

    /// Verify a proof against an expected root hash.
    ///
    /// This is the recommended verification method when you have a trusted
    /// root hash from a verified block header.
    #[cfg(not(feature = "no-light-client"))]
    pub fn verify_against_root(proof_hex: &str, expected_root_hex: &str) -> Result<bool> {
        let computed_root = Self::verify_query_proof(proof_hex, &[])?;
        Ok(computed_root == expected_root_hex)
    }

    /// Verify a proof against an expected root hash (stub).
    #[cfg(feature = "no-light-client")]
    pub fn verify_against_root(_proof_hex: &str, _expected_root_hex: &str) -> Result<bool> {
        Err(WillowError::ProofVerificationFailed(
            "Proof verification disabled with 'no-light-client' feature.".to_string(),
        ))
    }
}

/// Extension trait for QueryResponse to add verification methods.
pub trait QueryResponseExt {
    /// Verify the proof and compute the root hash.
    fn verify_proof(&self) -> Result<String>;
}

impl QueryResponseExt for crate::data::QueryResponse {
    fn verify_proof(&self) -> Result<String> {
        match &self.proof {
            Some(proof) => ProofVerifier::verify_query_proof(proof, &self.documents),
            None => Err(WillowError::ProofVerificationFailed(
                "Query response does not contain proof data".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_proof_hex() {
        let result = ProofVerifier::verify_query_proof("invalid_hex", &[]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid proof hex"));
    }

    #[test]
    fn test_empty_proof() {
        let proof = hex::encode(vec![]);
        let result = ProofVerifier::verify_query_proof(&proof, &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty proof"));
    }

    #[test]
    fn test_parse_proof_hex() {
        let data = vec![1, 2, 3, 4, 5];
        let hex_str = hex::encode(&data);
        let result = ProofVerifier::parse_proof_hex(&hex_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data);
    }
}
