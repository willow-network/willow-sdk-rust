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
        // Uncompressed without the leading 0x04 tag (as older `generate_did` stored it).
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

            // The 33-byte compressed key: the chain parses a DID document's
            // secp256k1 key as compressed (33 bytes) or 0x04-tagged (65 bytes).
            let public_key_vec = public_key.serialize().to_vec();

            (
                secret_key.secret_bytes().to_vec(),
                public_key_vec,
                "EcdsaSecp256k1VerificationKey2019",
            )
        }
    };

    // Derive the self-certifying DID from the public key (for secp256k1, the 33-byte
    // compressed form the chain hashes).
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

/// The message a nonce-signed request signs: a version line, then one per line the
/// DID, its key's id, the method, the path and query exactly as sent, the Unix
/// timestamp, the nonce, and the hex SHA-256 of the body (of no bytes, for a request
/// without one).
///
/// Only a request signed this way carries the DID's read rights: a Reader permission,
/// or a place on a priced subgrove's free-reader list.
pub fn signed_request_message(
    did: &str,
    public_key_id: &str,
    method: &str,
    path_and_query: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> String {
    format!(
        "willow-request-v2\n{did}\n{public_key_id}\n{method}\n{path_and_query}\n{timestamp}\n{nonce}\n{}",
        hex::encode(sha2::Sha256::digest(body))
    )
}

/// The message the older signature form signs: `{METHOD}:{PATH}:{TIMESTAMP}`, where
/// PATH is the path alone (the server verifies the request's path without its query),
/// so anything from the first `?` is dropped.
///
/// This form proves the DID but carries none of its read rights, and it can be
/// replayed with any body until the timestamp expires.
pub fn legacy_request_message(method: &str, path: &str, timestamp: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    format!("{method}:{path}:{timestamp}")
}

/// A fresh nonce for a nonce-signed request: 32 hex characters from 16 random bytes.
/// The server accepts 16 to 128 characters of `A-Z a-z 0-9 - _`, and each
/// (DID, nonce) once.
pub fn new_request_nonce() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// Signs a request message and encodes the signature as the server decodes
/// `X-Signature`: Ed25519 as hex, secp256k1 as `0x`-prefixed hex (the server reads
/// an unprefixed secp256k1 signature as base64 first, and most hex strings are valid
/// base64).
pub fn sign_request_message(
    message: &str,
    private_key_hex: &str,
    algorithm: SignatureAlgorithm,
) -> Result<String> {
    let signature = sign_challenge(message, private_key_hex, algorithm)?;
    Ok(match algorithm {
        SignatureAlgorithm::Secp256k1 => format!("0x{signature}"),
        SignatureAlgorithm::Ed25519 => signature,
    })
}

/// Headers for a request signed with a one-time nonce: `X-DID`, `X-Public-Key-ID`,
/// `X-Signature`, `X-Timestamp`, and `X-Nonce`, over [`signed_request_message`].
///
/// `path_and_query` is the request target exactly as the server receives it, query
/// string included, and `body` the exact bytes sent. The server accepts the timestamp
/// for 300 seconds and each nonce once, so sign every attempt of a retried request
/// anew.
pub fn sign_request_with_nonce(
    did: &str,
    public_key_id: &str,
    private_key_hex: &str,
    algorithm: SignatureAlgorithm,
    method: &str,
    path_and_query: &str,
    body: &[u8],
) -> Result<Vec<(String, String)>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| WillowError::Crypto("system clock is before 1970".to_string()))?
        .as_secs()
        .to_string();
    sign_request_with_nonce_at(
        did,
        public_key_id,
        private_key_hex,
        algorithm,
        method,
        path_and_query,
        body,
        &timestamp,
        &new_request_nonce(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_request_with_nonce_at(
    did: &str,
    public_key_id: &str,
    private_key_hex: &str,
    algorithm: SignatureAlgorithm,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    timestamp: &str,
    nonce: &str,
) -> Result<Vec<(String, String)>> {
    let message = signed_request_message(
        did,
        public_key_id,
        method,
        path_and_query,
        timestamp,
        nonce,
        body,
    );
    let signature = sign_request_message(&message, private_key_hex, algorithm)?;
    Ok(vec![
        ("X-DID".to_string(), did.to_string()),
        ("X-Public-Key-ID".to_string(), public_key_id.to_string()),
        ("X-Signature".to_string(), signature),
        ("X-Timestamp".to_string(), timestamp.to_string()),
        ("X-Nonce".to_string(), nonce.to_string()),
    ])
}

/// Verify a signature
pub fn verify_signature(
    message: &str,
    signature_hex: &str,
    public_key_hex: &str,
    algorithm: SignatureAlgorithm,
) -> Result<bool> {
    let signature_bytes = hex::decode(signature_hex.trim_start_matches("0x"))?;
    let public_key_bytes = hex::decode(public_key_hex.trim_start_matches("0x"))?;
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

            // 33-byte compressed, 65-byte tagged, or 64-byte untagged uncompressed.
            let public_key =
                Secp256k1PublicKey::from_slice(&secp256k1_compressed(&public_key_bytes)?)?;

            // Hash message with Keccak256
            let mut hasher = Keccak256::new();
            hasher.update(message_bytes);
            let message_hash = hasher.finalize();

            let message = Message::from_digest_slice(&message_hash)
                .map_err(|_| WillowError::Crypto("Failed to create message".to_string()))?;

            // Like the server: 64-byte compact, else DER; verify_ecdsa takes lower-S only.
            let signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes)
                .or_else(|_| secp256k1::ecdsa::Signature::from_der(&signature_bytes))?;

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

    /// The api-server's test vector (`the_signed_message_is_eight_lines`), byte for byte.
    const SIGNED_MESSAGE_VECTOR: &str = "willow-request-v2\ndid:willow:a\ndid:willow:a#key-1\nPOST\n/query/sg?x=1\n1700000000\nabcdefghijklmnop\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

    /// The key whose seed is 32 bytes of 0x03, for both algorithms.
    const VECTOR_SEED: &str = "0303030303030303030303030303030303030303030303030303030303030303";

    /// Signatures over the vector, from an independent implementation of the
    /// server's verification.
    const VECTOR_ED25519_SIGNATURE: &str = "c117313c0d01641340e398d9a7a9ff024a1c6672bca16bbcb99e6fe2738f82e77870bd2c30dc62d6c50cea32a3b21086730d9c25297831dd83bc797c5b394d0d";
    const VECTOR_SECP256K1_SIGNATURE: &str = "bfbad8ec000c66ed30349070db245db0c45249293c545e35dc997d6427d3223830787244d5b3bb7e8a1b39bdba0c62261e02344a515f5e8e89f678e17d4b976d";

    fn vector_headers(algorithm: SignatureAlgorithm) -> Vec<(String, String)> {
        sign_request_with_nonce_at(
            "did:willow:a",
            "did:willow:a#key-1",
            VECTOR_SEED,
            algorithm,
            "POST",
            "/query/sg?x=1",
            b"{}",
            "1700000000",
            "abcdefghijklmnop",
        )
        .unwrap()
    }

    #[test]
    fn signed_request_message_matches_the_server_vector() {
        assert_eq!(
            signed_request_message(
                "did:willow:a",
                "did:willow:a#key-1",
                "POST",
                "/query/sg?x=1",
                "1700000000",
                "abcdefghijklmnop",
                b"{}",
            ),
            SIGNED_MESSAGE_VECTOR
        );
    }

    #[test]
    fn nonce_signed_headers_ed25519_known_answer() {
        let headers = vector_headers(SignatureAlgorithm::Ed25519);
        let expected: Vec<(String, String)> = [
            ("X-DID", "did:willow:a"),
            ("X-Public-Key-ID", "did:willow:a#key-1"),
            ("X-Signature", VECTOR_ED25519_SIGNATURE),
            ("X-Timestamp", "1700000000"),
            ("X-Nonce", "abcdefghijklmnop"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(headers, expected);
    }

    #[test]
    fn nonce_signed_headers_secp256k1_known_answer() {
        let headers = vector_headers(SignatureAlgorithm::Secp256k1);
        let signature = &headers.iter().find(|(k, _)| k == "X-Signature").unwrap().1;
        // 0x-prefixed: the server reads an unprefixed secp256k1 signature as base64 first.
        assert_eq!(signature, &format!("0x{VECTOR_SECP256K1_SIGNATURE}"));
        assert!(verify_signature(
            SIGNED_MESSAGE_VECTOR,
            signature,
            "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
            SignatureAlgorithm::Secp256k1,
        )
        .unwrap());
        // The same signature in DER verifies too, as on the server.
        assert!(verify_signature(
            SIGNED_MESSAGE_VECTOR,
            "3045022100bfbad8ec000c66ed30349070db245db0c45249293c545e35dc997d6427d32238022030787244d5b3bb7e8a1b39bdba0c62261e02344a515f5e8e89f678e17d4b976d",
            "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
            SignatureAlgorithm::Secp256k1,
        )
        .unwrap());
    }

    #[test]
    fn legacy_request_message_signs_the_path_alone() {
        assert_eq!(
            legacy_request_message("GET", "/data/sg/k?include_proof=true", "1700000000"),
            "GET:/data/sg/k:1700000000"
        );
        assert_eq!(
            legacy_request_message("GET", "/data/sg/k", "1700000000"),
            "GET:/data/sg/k:1700000000"
        );
    }

    #[test]
    fn request_nonces_are_wellformed_and_fresh() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let nonce = new_request_nonce();
            assert!((16..=128).contains(&nonce.len()));
            assert!(nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
            assert!(seen.insert(nonce));
        }
    }

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
        assert_eq!(did_info.public_key.len(), 33); // Compressed, as the chain parses it
    }

    /// MANDATORY acceptance vector: this exact Ed25519 key MUST derive this exact DID.
    /// If it does not, the derivation is wrong and must not be shipped.
    #[test]
    fn test_ed25519_did_acceptance_vector() {
        let public_key =
            hex::decode("a003201e65e47d578ad9bb17cb1d3590e9f504f55eac6ee40002e3ab9517c49c")
                .unwrap();
        let did = did_from_public_key(SignatureAlgorithm::Ed25519, &public_key).unwrap();
        assert_eq!(
            did,
            "did:willow:zDZ1Qqspppayjd9LF3Pkebq64Fa2PuK8zFQDDc11citB2"
        );
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
