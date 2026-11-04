//! Proof verification for Willow reads.
//!
//! A proof is checked here only for what it binds: an Item at a given GroveDB path and key whose
//! bytes are a given value ([`ProofVerifier::verify_item_at_path`]). The root it computes is the
//! proof's own, so a read is verified only once that root is compared with one the caller trusts
//! (for chain state, the app hash of the CometBFT header after the proof's block, which
//! [`crate::light_client::LightClient::verify_item`] checks). A lone root hash, a proof of
//! another path or key, or a proof that names no path proves nothing.
//!
//! Disable with the `no-light-client` feature for minimal dependencies.

use crate::errors::{Result, WillowError};
use serde_json::Value;

/// The GroveDB path of a subgrove's data: `[subgroves, subgrove_id, data]`.
pub fn subgrove_data_path(subgrove_id: &str) -> Vec<Vec<u8>> {
    vec![
        b"subgroves".to_vec(),
        subgrove_id.as_bytes().to_vec(),
        b"data".to_vec(),
    ]
}

const PATHLESS: &str = "a proof checked without the GroveDB path and key it is for proves only a \
                        root hash, not any data; use ProofVerifier::verify_item_at_path";

/// Proof verification functionality.
pub struct ProofVerifier;

impl ProofVerifier {
    /// Not supported: always [`WillowError::Unsupported`].
    ///
    /// It checked a proof at the empty path with no key and returned the root it computed,
    /// which a lone `Push(Hash(root))` passes for any root, and it bound none of `documents`.
    #[deprecated(note = "proves only a root hash; use ProofVerifier::verify_item_at_path")]
    pub fn verify_query_proof(_proof_hex: &str, _documents: &[Value]) -> Result<String> {
        Err(WillowError::Unsupported(PATHLESS.to_string()))
    }

    /// Not supported: always [`WillowError::Unsupported`].
    ///
    /// It checked a proof at the empty path and ignored `value`.
    #[deprecated(note = "binds no path or value; use ProofVerifier::verify_item_at_path")]
    pub fn verify_item_proof(_proof_hex: &str, _key: &str, _value: &Value) -> Result<String> {
        Err(WillowError::Unsupported(PATHLESS.to_string()))
    }

    /// Not supported: always [`WillowError::Unsupported`].
    ///
    /// It compared the root of a proof checked at the empty path with `expected_root_hex`, which
    /// a lone `Push(Hash(expected_root))` passes.
    #[deprecated(note = "proves only a root hash; use ProofVerifier::verify_item_against_root")]
    pub fn verify_against_root(_proof_hex: &str, _expected_root_hex: &str) -> Result<bool> {
        Err(WillowError::Unsupported(PATHLESS.to_string()))
    }

    /// Parse proof bytes without verification.
    ///
    /// Always available for proof inspection.
    pub fn parse_proof_hex(proof_hex: &str) -> Result<Vec<u8>> {
        hex::decode(proof_hex)
            .map_err(|e| WillowError::ProofVerificationFailed(format!("Invalid proof hex: {}", e)))
    }

    /// Check that `proof_hex` proves an Item at `key` in the subtree at `path` whose bytes are
    /// `value`, and return the root it computes. See
    /// [`crate::grovedb_envelope::verify_item_at_path`] for what passes.
    ///
    /// The root is the proof's own: the value is verified only once the caller finds it equal to
    /// a root it trusts ([`Self::verify_item_against_root`]).
    #[cfg(not(feature = "no-light-client"))]
    pub fn verify_item_at_path(
        proof_hex: &str,
        path: &[Vec<u8>],
        key: &[u8],
        value: &[u8],
    ) -> Result<[u8; 32]> {
        let proof = Self::parse_proof_hex(proof_hex)?;
        let (root, item) = crate::grovedb_envelope::verify_item_at_path(&proof, path, key)?;
        if item != value {
            return Err(WillowError::ProofVerificationFailed(
                "the proof proves another value at the path and key".to_string(),
            ));
        }
        Ok(root)
    }

    /// [`Self::verify_item_at_path`], with the root it computes required to be `trusted_root`.
    #[cfg(not(feature = "no-light-client"))]
    pub fn verify_item_against_root(
        proof_hex: &str,
        path: &[Vec<u8>],
        key: &[u8],
        value: &[u8],
        trusted_root: &[u8; 32],
    ) -> Result<()> {
        let root = Self::verify_item_at_path(proof_hex, path, key, value)?;
        if &root != trusted_root {
            return Err(WillowError::ProofVerificationFailed(format!(
                "Root hash mismatch: the proof computes {}, not the trusted root {}",
                hex::encode(root),
                hex::encode(trusted_root)
            )));
        }
        Ok(())
    }

    /// Not available with the `no-light-client` feature: always [`WillowError::Unsupported`].
    #[cfg(feature = "no-light-client")]
    pub fn verify_item_at_path(
        _proof_hex: &str,
        _path: &[Vec<u8>],
        _key: &[u8],
        _value: &[u8],
    ) -> Result<[u8; 32]> {
        Err(WillowError::Unsupported(
            "proof verification is disabled with the no-light-client feature".to_string(),
        ))
    }

    /// Not available with the `no-light-client` feature: always [`WillowError::Unsupported`].
    #[cfg(feature = "no-light-client")]
    pub fn verify_item_against_root(
        _proof_hex: &str,
        _path: &[Vec<u8>],
        _key: &[u8],
        _value: &[u8],
        _trusted_root: &[u8; 32],
    ) -> Result<()> {
        Err(WillowError::Unsupported(
            "proof verification is disabled with the no-light-client feature".to_string(),
        ))
    }
}

/// Extension trait for QueryResponse to add verification methods.
pub trait QueryResponseExt {
    /// Not supported: always [`WillowError::Unsupported`]. A query's documents come without
    /// their keys, so nothing binds them to the proof (see [`crate::data::DataOperations::query`]).
    fn verify_proof(&self) -> Result<String>;
}

impl QueryResponseExt for crate::data::QueryResponse {
    fn verify_proof(&self) -> Result<String> {
        Err(WillowError::Unsupported(
            "a query's documents can't be verified: the API serves them without their keys, and \
             nothing binds them to the proof or to the query's selection"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn the_pathless_checks_refuse() {
        let mut lone = vec![0x00, 0x21, 0x01];
        lone.extend_from_slice(&[7; 32]);
        lone.extend_from_slice(&[0x00, 0x01]);
        let lone = hex::encode(lone);
        let root = hex::encode([7; 32]);
        for result in [
            ProofVerifier::verify_query_proof(&lone, &[]).map(|_| ()),
            ProofVerifier::verify_item_proof(&lone, "k", &Value::Null).map(|_| ()),
            ProofVerifier::verify_against_root(&lone, &root).map(|_| ()),
        ] {
            assert!(
                matches!(result, Err(WillowError::Unsupported(_))),
                "{result:?}"
            );
        }
    }

    #[cfg(not(feature = "no-light-client"))]
    #[test]
    fn a_lone_root_hash_proves_no_item() {
        let mut lone = vec![0x00, 0x21, 0x01];
        lone.extend_from_slice(&[7; 32]);
        lone.extend_from_slice(&[0x00, 0x01]);
        let lone = hex::encode(lone);
        for path in [vec![], subgrove_data_path("sg-1")] {
            assert!(ProofVerifier::verify_item_at_path(&lone, &path, b"k", b"{}").is_err());
            assert!(
                ProofVerifier::verify_item_against_root(&lone, &path, b"k", b"{}", &[7; 32])
                    .is_err()
            );
        }
    }

    #[test]
    fn test_parse_proof_hex() {
        let data = vec![1, 2, 3, 4, 5];
        let hex_str = hex::encode(&data);
        let result = ProofVerifier::parse_proof_hex(&hex_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data);
        assert!(ProofVerifier::parse_proof_hex("invalid_hex").is_err());
    }
}
