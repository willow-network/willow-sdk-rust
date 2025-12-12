//! Authentication utilities for Willow SDK

use crate::errors::{WillowError, Result};
use crate::types::{DidDocument, PublicKey, SignatureAlgorithm};

// Re-export types that may be needed by examples
pub use crate::types::DidInfo;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use secp256k1::{Message, PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

/// Generate a new DID with keypair
pub fn generate_did(algorithm: SignatureAlgorithm) -> Result<DidInfo> {
    let (private_key, public_key, key_type) = match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let secret_key_bytes: [u8; 32] = rand::random();
            let signing_key = SigningKey::from_bytes(&secret_key_bytes);
            let private_key = signing_key.to_bytes().to_vec();
            let public_key = signing_key.verifying_key().to_bytes().to_vec();
            (private_key, public_key, "Ed25519VerificationKey2018")
        }
        SignatureAlgorithm::Secp256k1 => {
            let secp = Secp256k1::new();
            let secret_key = SecretKey::new(&mut OsRng);
            let public_key = Secp256k1PublicKey::from_secret_key(&secp, &secret_key);

            // Store uncompressed public key (without 0x04 prefix)
            let public_key_bytes = public_key.serialize_uncompressed();
            let public_key_vec = public_key_bytes[1..].to_vec(); // Remove 0x04 prefix

            (
                secret_key.secret_bytes().to_vec(),
                public_key_vec,
                "EcdsaSecp256k1VerificationKey2019",
            )
        }
    };

    // Create DID
    let did_suffix = hex::encode(&public_key[..8]);
    let did = format!(
        "did:willow:{}:{}",
        algorithm.as_str().to_lowercase(),
        did_suffix
    );
    let public_key_id = format!("{}#key-1", did);

    // Create DID document
    let did_document = DidDocument {
        id: did.clone(),
        public_keys: vec![PublicKey {
            id: public_key_id.clone(),
            key_type: key_type.to_string(),
            controller: did.clone(),
            public_key_hex: Some(hex::encode(&public_key)),
            public_key_base58: None,
        }],
        authentication: vec![public_key_id.clone()],
        service: vec![],
        created: Utc::now().timestamp() as u64,
        updated: Utc::now().timestamp() as u64,
        proof: None,
    };

    Ok(DidInfo {
        did,
        private_key,
        public_key,
        public_key_id,
        did_document,
        algorithm,
    })
}

/// Sign a challenge message
pub fn sign_challenge(
    message: &str,
    private_key_hex: &str,
    algorithm: SignatureAlgorithm,
) -> Result<String> {
    let private_key_bytes = hex::decode(private_key_hex)?;
    let message_bytes = message.as_bytes();

    let signature = match algorithm {
        SignatureAlgorithm::Ed25519 => {
            if private_key_bytes.len() != 32 {
                return Err(WillowError::Validation(
                    "Ed25519 private key must be 32 bytes".to_string(),
                ));
            }

            let private_key_array: [u8; 32] = private_key_bytes.try_into().map_err(|_| {
                WillowError::Crypto("Invalid Ed25519 private key length".to_string())
            })?;
            let signing_key = SigningKey::from_bytes(&private_key_array);

            signing_key.sign(message_bytes).to_bytes().to_vec()
        }
        SignatureAlgorithm::Secp256k1 => {
            let secp = Secp256k1::new();
            let secret_key = SecretKey::from_slice(&private_key_bytes)?;

            // Hash message with Keccak256 (Ethereum style)
            let mut hasher = Keccak256::new();
            hasher.update(message_bytes);
            let message_hash = hasher.finalize();

            let message = Message::from_digest_slice(&message_hash)
                .map_err(|_| WillowError::Crypto("Failed to create message".to_string()))?;

            let sig = secp.sign_ecdsa(&message, &secret_key);
            sig.serialize_compact().to_vec()
        }
    };

    Ok(hex::encode(signature))
}

/// Verify a signature
pub fn verify_signature(
    message: &str,
    signature_hex: &str,
    public_key_hex: &str,
    algorithm: SignatureAlgorithm,
) -> Result<bool> {
    let signature_bytes = hex::decode(signature_hex)?;
    let public_key_bytes = hex::decode(public_key_hex)?;
    let message_bytes = message.as_bytes();

    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            if signature_bytes.len() != 64 {
                return Ok(false);
            }
            if public_key_bytes.len() != 32 {
                return Ok(false);
            }

            let public_key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
                WillowError::Crypto("Invalid Ed25519 public key length".to_string())
            })?;
            let verifying_key = VerifyingKey::from_bytes(&public_key_array)
                .map_err(|_| WillowError::Crypto("Invalid Ed25519 public key".to_string()))?;

            let signature_array: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| WillowError::Crypto("Invalid Ed25519 signature length".to_string()))?;
            let signature = Signature::from_bytes(&signature_array);

            Ok(verifying_key.verify(message_bytes, &signature).is_ok())
        }
        SignatureAlgorithm::Secp256k1 => {
            let secp = Secp256k1::new();

            // Add 0x04 prefix for uncompressed public key
            let mut full_public_key = vec![0x04];
            full_public_key.extend_from_slice(&public_key_bytes);

            let public_key = Secp256k1PublicKey::from_slice(&full_public_key)?;

            // Hash message with Keccak256
            let mut hasher = Keccak256::new();
            hasher.update(message_bytes);
            let message_hash = hasher.finalize();

            let message = Message::from_digest_slice(&message_hash)
                .map_err(|_| WillowError::Crypto("Failed to create message".to_string()))?;

            let signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes)?;

            Ok(secp.verify_ecdsa(&message, &signature, &public_key).is_ok())
        }
    }
}

/// Detect signature algorithm from DID
pub fn detect_algorithm_from_did(did: &str) -> SignatureAlgorithm {
    if did.contains("ed25519") {
        SignatureAlgorithm::Ed25519
    } else if did.contains("secp256k1") {
        SignatureAlgorithm::Secp256k1
    } else {
        // Default to Ed25519
        SignatureAlgorithm::Ed25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519_did() {
        let did_info = generate_did(SignatureAlgorithm::Ed25519).unwrap();
        assert!(did_info.did.starts_with("did:willow:ed25519:"));
        assert_eq!(did_info.private_key.len(), 32);
        assert_eq!(did_info.public_key.len(), 32);
    }

    #[test]
    fn test_generate_secp256k1_did() {
        let did_info = generate_did(SignatureAlgorithm::Secp256k1).unwrap();
        assert!(did_info.did.starts_with("did:willow:secp256k1:"));
        assert_eq!(did_info.private_key.len(), 32);
        assert_eq!(did_info.public_key.len(), 64); // Uncompressed without prefix
    }

    #[test]
    fn test_sign_and_verify_ed25519() {
        let did_info = generate_did(SignatureAlgorithm::Ed25519).unwrap();
        let message = "test message";

        let signature = sign_challenge(
            message,
            &did_info.private_key_hex(),
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();

        let is_valid = verify_signature(
            message,
            &signature,
            &did_info.public_key_hex(),
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_sign_and_verify_secp256k1() {
        let did_info = generate_did(SignatureAlgorithm::Secp256k1).unwrap();
        let message = "test message";

        let signature = sign_challenge(
            message,
            &did_info.private_key_hex(),
            SignatureAlgorithm::Secp256k1,
        )
        .unwrap();

        let is_valid = verify_signature(
            message,
            &signature,
            &did_info.public_key_hex(),
            SignatureAlgorithm::Secp256k1,
        )
        .unwrap();

        assert!(is_valid);
    }
}
