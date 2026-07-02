//! Authentication utilities for Willow SDK

use crate::errors::{Result, WillowError};
use crate::types::{DidDocument, PublicKey, SignatureAlgorithm};

// Re-export types that may be needed by examples
pub use crate::types::DidInfo;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use secp256k1::{Message, PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256, Sha3_256};

/// Multibase prefix marking a base58btc-encoded value (`z`).
const MULTIBASE_BASE58BTC: char = 'z';

/// Multicodec varint prefix for an Ed25519 public key (`0xed 0x01`).
const MULTICODEC_ED25519_PUB: [u8; 2] = [0xed, 0x01];

/// Multicodec varint prefix for a secp256k1 (compressed) public key (`0xe7 0x01`).
const MULTICODEC_SECP256K1_PUB: [u8; 2] = [0xe7, 0x01];

/// Derive a self-certifying Willow DID from a public key.
///
/// Willow's chain requires every new DID id to be bound to its key via:
///
/// ```text
/// did = "did:willow:z" + base58btc( SHA3-256( multicodec_prefix || public_key ) )
/// ```
///
/// where:
/// - `SHA3-256` is FIPS-202 SHA3-256 (not Keccak-256),
/// - `multicodec_prefix` is `0xed 0x01` for Ed25519 and `0xe7 0x01` for secp256k1,
/// - `base58btc` uses the Bitcoin alphabet (leading `0x00` bytes become leading `1`s),
/// - the literal `z` is the multibase base58btc marker.
///
/// Key material expectations:
/// - Ed25519: `public_key` is the 32-byte key.
/// - secp256k1: any of the 33-byte compressed, 65-byte uncompressed (`0x04` prefix),
///   or 64-byte uncompressed-without-prefix encodings is accepted and normalized to
///   the 33-byte compressed form before hashing.
///
/// The id is fully determined by the key, so it cannot be chosen. See
/// [`generate_did`] for the two-step (pre-fund then register) bootstrap.
pub fn did_from_public_key(algorithm: SignatureAlgorithm, public_key: &[u8]) -> Result<String> {
    let (prefix, key_bytes): (&[u8], Vec<u8>) = match algorithm {
        SignatureAlgorithm::Ed25519 => {
            if public_key.len() != 32 {
                return Err(WillowError::Crypto(
                    "Ed25519 public key must be 32 bytes".to_string(),
                ));
            }
            (&MULTICODEC_ED25519_PUB, public_key.to_vec())
        }
        SignatureAlgorithm::Secp256k1 => {
            (&MULTICODEC_SECP256K1_PUB, secp256k1_compressed(public_key)?)
        }
    };

    let mut input = Vec::with_capacity(prefix.len() + key_bytes.len());
    input.extend_from_slice(prefix);
    input.extend_from_slice(&key_bytes);

    // FIPS-202 SHA3-256 (NOT Keccak-256; the two differ).
    let digest = Sha3_256::digest(&input);
    let encoded = bs58::encode(digest).into_string();

    Ok(format!("did:willow:{}{}", MULTIBASE_BASE58BTC, encoded))
}

/// Normalize any accepted secp256k1 public-key encoding to its 33-byte compressed form.
fn secp256k1_compressed(public_key: &[u8]) -> Result<Vec<u8>> {
    let parsed = match public_key.len() {
        // Compressed (0x02/0x03 prefix) or uncompressed (0x04 prefix).
        33 | 65 => Secp256k1PublicKey::from_slice(public_key)?,
        // Uncompressed without the leading 0x04 tag (as stored by `generate_did`).
        64 => {
            let mut with_prefix = Vec::with_capacity(65);
            with_prefix.push(0x04);
            with_prefix.extend_from_slice(public_key);
            Secp256k1PublicKey::from_slice(&with_prefix)?
        }
        _ => {
            return Err(WillowError::Crypto(
                "secp256k1 public key must be 33, 64, or 65 bytes".to_string(),
            ));
        }
    };
    Ok(parsed.serialize().to_vec())
}

/// Generate a new DID with keypair.
///
/// The returned [`DidInfo::did`] is *self-certifying*: it is derived from the freshly
/// generated public key via [`did_from_public_key`], so it cannot be chosen. Because the
/// id is bound to the key, a new DID must be funded **before** it is registered:
///
/// 1. Generate the keypair here and read the derived `did`.
/// 2. Have an existing account transfer at least the registration fee to that `did`.
/// 3. Register with `client.consensus().register_did(...)`; the fee is paid from the
///    balance funded in step 2.
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

    // Derive the self-certifying DID from the public key. For secp256k1 the stored
    // `public_key` is the uncompressed key without its 0x04 tag; `did_from_public_key`
    // normalizes it to the 33-byte compressed form the chain hashes.
    let did = did_from_public_key(algorithm, &public_key)?;
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

/// Detect signature algorithm from DID.
///
/// Note: self-certifying `did:willow:z...` ids do not encode the algorithm in a
/// human-readable form (the multicodec prefix is inside the hash preimage, not the
/// string), so those ids fall through to the Ed25519 default. Callers holding a
/// secp256k1 key should track the algorithm alongside the DID rather than inferring
/// it from the string.
pub fn detect_algorithm_from_did(did: &str) -> SignatureAlgorithm {
    if did.contains("ed25519") {
        SignatureAlgorithm::Ed25519
    } else if did.contains("secp256k1") {
        SignatureAlgorithm::Secp256k1
    } else {
        // Default to Ed25519 (also covers self-certifying `did:willow:z...` ids).
        SignatureAlgorithm::Ed25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519_did() {
        let did_info = generate_did(SignatureAlgorithm::Ed25519).unwrap();
        // Self-certifying id: did:willow:z<base58btc(SHA3-256(prefix||pubkey))>.
        assert!(did_info.did.starts_with("did:willow:z"));
        assert_eq!(did_info.public_key_id, format!("{}#key-1", did_info.did));
        // The id must be reproducible from the public key alone.
        assert_eq!(
            did_info.did,
            did_from_public_key(SignatureAlgorithm::Ed25519, &did_info.public_key).unwrap()
        );
        assert_eq!(did_info.private_key.len(), 32);
        assert_eq!(did_info.public_key.len(), 32);
    }

    #[test]
    fn test_generate_secp256k1_did() {
        let did_info = generate_did(SignatureAlgorithm::Secp256k1).unwrap();
        assert!(did_info.did.starts_with("did:willow:z"));
        assert_eq!(did_info.public_key_id, format!("{}#key-1", did_info.did));
        assert_eq!(
            did_info.did,
            did_from_public_key(SignatureAlgorithm::Secp256k1, &did_info.public_key).unwrap()
        );
        assert_eq!(did_info.private_key.len(), 32);
        assert_eq!(did_info.public_key.len(), 64); // Uncompressed without prefix
    }

    /// MANDATORY acceptance vector: this exact Ed25519 key MUST derive this exact DID.
    /// If it does not, the derivation is wrong and must not be shipped.
    #[test]
    fn test_ed25519_did_acceptance_vector() {
        let public_key =
            hex::decode("a003201e65e47d578ad9bb17cb1d3590e9f504f55eac6ee40002e3ab9517c49c")
                .unwrap();
        let did = did_from_public_key(SignatureAlgorithm::Ed25519, &public_key).unwrap();
        assert_eq!(did, "did:willow:zDZ1Qqspppayjd9LF3Pkebq64Fa2PuK8zFQDDc11citB2");
    }

    /// secp256k1 derivation must be invariant across compressed / uncompressed
    /// (with and without the 0x04 tag) encodings of the same key.
    #[test]
    fn test_secp256k1_did_encoding_invariant() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let public_key = Secp256k1PublicKey::from_secret_key(&secp, &secret);

        let compressed = public_key.serialize().to_vec(); // 33 bytes
        let uncompressed = public_key.serialize_uncompressed().to_vec(); // 65 bytes (0x04)
        let uncompressed_no_prefix = uncompressed[1..].to_vec(); // 64 bytes

        let from_compressed =
            did_from_public_key(SignatureAlgorithm::Secp256k1, &compressed).unwrap();
        let from_uncompressed =
            did_from_public_key(SignatureAlgorithm::Secp256k1, &uncompressed).unwrap();
        let from_no_prefix =
            did_from_public_key(SignatureAlgorithm::Secp256k1, &uncompressed_no_prefix).unwrap();

        assert!(from_compressed.starts_with("did:willow:z"));
        assert_eq!(from_compressed, from_uncompressed);
        assert_eq!(from_compressed, from_no_prefix);
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
