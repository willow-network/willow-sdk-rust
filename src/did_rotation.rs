//! Building blocks for rotating the signing key on a Willow DID.
//!
//! Rotation is an `UpdateDid` transaction signed by the key currently in the
//! on-chain document, carrying a replacement document that lists the new key.
//! The chain does not validate the replacement's structure, so a document whose
//! `authentication` set names a key nobody holds bricks the DID permanently —
//! no further admin transaction can ever be signed for it.
//!
//! Everything here exists to make that unreachable: [`rotated_document`] derives
//! the replacement from the live document instead of inventing one,
//! [`assert_key_controls_document`] proves the held private key really signs for
//! the replacement before it is broadcast, and [`update_did_signing_message`] is
//! the single definition of the bytes the consensus handler verifies.

use std::path::Path;

use ed25519_dalek::SigningKey;
use willow_types::consensus::transactions::{DidDocument, PublicKey};

use crate::auth::{sign_challenge, verify_signature};
use crate::errors::{Result, WillowError};
use crate::types::SignatureAlgorithm;

/// Key type the chain's ed25519 verifier dispatches on.
pub const ED25519_VERIFICATION_KEY_2018: &str = "Ed25519VerificationKey2018";

/// Message signed by the anti-brick probe. Never broadcast — it exists only to
/// prove the held private key matches the document's public key.
const PROBE_MESSAGE: &str = "willow-did-rotation-anti-brick-probe";

/// The exact bytes an `UpdateDid` signature covers.
///
/// Must stay byte-identical to `process_update_did` in the monorepo
/// (`crates/consensus/src/willow_cometbft/identity_transactions.rs`), which
/// re-serializes the document it decoded off the wire and formats it the same
/// way. Passing the same `willow-types` struct is what makes the two agree.
pub fn update_did_signing_message(new_document: &DidDocument, nonce: u64) -> Result<String> {
    let new_doc_json = serde_json::to_string(new_document)?;
    Ok(format!("UpdateDid\n{}\n{}", new_doc_json, nonce))
}

/// Derive the replacement document from the live on-chain one.
///
/// Carries `id`, `service`, and `created` across untouched; replaces
/// `public_keys` / `authentication` with the single new key and bumps
/// `updated`. `proof` is dropped: any proof on the current document attests to
/// the key being retired, so keeping it would leave a stale attestation behind.
pub fn rotated_document(
    current: &DidDocument,
    new_key_id: &str,
    new_public_key_hex: &str,
    updated: u64,
) -> DidDocument {
    DidDocument {
        id: current.id.clone(),
        public_keys: vec![PublicKey {
            id: new_key_id.to_string(),
            key_type: ED25519_VERIFICATION_KEY_2018.to_string(),
            controller: current.id.clone(),
            public_key_base58: None,
            public_key_hex: Some(new_public_key_hex.to_string()),
        }],
        authentication: vec![new_key_id.to_string()],
        service: current.service.clone(),
        created: current.created,
        updated,
        proof: None,
    }
}

/// Resolve a public key's ed25519 bytes as hex, using the same precedence as
/// the chain's verifier: `public_key_hex` first (0x-prefix tolerated), then
/// `public_key_base58`.
pub fn ed25519_public_key_hex(public_key: &PublicKey) -> Option<String> {
    if let Some(hex_value) = &public_key.public_key_hex {
        return Some(hex_value.trim_start_matches("0x").to_string());
    }
    let base58 = public_key.public_key_base58.as_ref()?;
    bs58::decode(base58).into_vec().ok().map(hex::encode)
}

/// The anti-brick gate: refuse to broadcast a document the held key cannot sign
/// for.
///
/// Checks, in order:
/// 1. `authentication` is non-empty — an empty set locks the DID out of every
///    signed operation.
/// 2. every id in `authentication` resolves to an entry in `public_keys` — an
///    unresolvable id is an authentication slot nobody can ever fill.
/// 3. at least one authenticating key verifies a freshly signed probe made with
///    `private_key_hex` — the private half is really in hand.
///
/// Returns the id of the key that answered the probe.
pub fn assert_key_controls_document(
    document: &DidDocument,
    private_key_hex: &str,
) -> Result<String> {
    if document.authentication.is_empty() {
        return Err(WillowError::Validation(format!(
            "refusing to rotate {}: replacement document has an empty authentication set, \
             which would permanently brick the DID",
            document.id
        )));
    }

    let mut resolved = Vec::with_capacity(document.authentication.len());
    for key_id in &document.authentication {
        let public_key = document
            .public_keys
            .iter()
            .find(|pk| &pk.id == key_id)
            .ok_or_else(|| {
                WillowError::Validation(format!(
                    "refusing to rotate {}: authentication lists {:?}, which is not in \
                     public_keys, so no key could ever authenticate as this DID",
                    document.id, key_id
                ))
            })?;
        resolved.push(public_key);
    }

    let probe_signature =
        sign_challenge(PROBE_MESSAGE, private_key_hex, SignatureAlgorithm::Ed25519)?;

    for public_key in resolved {
        let Some(public_key_hex) = ed25519_public_key_hex(public_key) else {
            continue;
        };
        let verified = verify_signature(
            PROBE_MESSAGE,
            &probe_signature,
            &public_key_hex,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap_or(false);
        if verified {
            return Ok(public_key.id.clone());
        }
    }

    Err(WillowError::Validation(format!(
        "refusing to rotate {}: none of the replacement document's authentication keys \
         verify a probe signed with the new private key — the key file and the document \
         disagree, and broadcasting would permanently brick the DID",
        document.id
    )))
}

/// Write a private key to `path`, creating it mode 0600 and refusing to touch a
/// file that already exists.
///
/// Created before anything is broadcast: a rotation whose new key was never
/// persisted is the same as a brick.
pub fn write_new_key_file(path: &Path, private_key_hex: &str) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            WillowError::Validation(format!(
                "refusing to overwrite existing key file {} — move it aside or pick another \
                 --new-key-out path",
                path.display()
            ))
        } else {
            WillowError::Io(e)
        }
    })?;
    file.write_all(private_key_hex.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Read a hex private key previously written by [`write_new_key_file`].
pub fn read_key_file(path: &Path) -> Result<String> {
    let contents = std::fs::read_to_string(path)?;
    let trimmed = contents.trim().to_string();
    parse_ed25519_seed(&trimmed).map(|_| trimmed)
}

/// Decode a 32-byte ed25519 seed from hex, tolerating a `0x` prefix.
pub fn parse_ed25519_seed(private_key_hex: &str) -> Result<SigningKey> {
    let bare = private_key_hex.trim().trim_start_matches("0x");
    let bytes = hex::decode(bare)
        .map_err(|e| WillowError::Validation(format!("private key is not valid hex: {}", e)))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        WillowError::Validation("ed25519 private key must be exactly 32 bytes".to_string())
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use willow_types::consensus::transactions::ServiceEndpoint;

    // RFC 8032 §7.1 TEST 1 — the published vector the devnet accounts use.
    const RFC8032_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC8032_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    // RFC 8032 §7.1 TEST 2 — a second known-good pair, used as "some other key".
    const OTHER_SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const OTHER_PUBLIC: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

    fn current_document() -> DidDocument {
        DidDocument {
            id: "did:willow:validator1".to_string(),
            public_keys: vec![PublicKey {
                id: "did:willow:validator1#key-1".to_string(),
                key_type: ED25519_VERIFICATION_KEY_2018.to_string(),
                controller: "did:willow:validator1".to_string(),
                public_key_base58: None,
                public_key_hex: Some(RFC8032_PUBLIC.to_string()),
            }],
            authentication: vec!["did:willow:validator1#key-1".to_string()],
            service: vec![ServiceEndpoint {
                id: "did:willow:validator1#api".to_string(),
                service_type: "WillowApi".to_string(),
                service_endpoint: "http://localhost:3031".to_string(),
            }],
            created: 1_700_000_000,
            updated: 1_700_000_000,
            proof: None,
        }
    }

    // ========================================================================
    // Signing message — must match the consensus handler byte for byte
    // ========================================================================

    #[test]
    fn signing_message_matches_the_consensus_handler_construction() {
        let document = rotated_document(
            &current_document(),
            "did:willow:validator1#key-1",
            OTHER_PUBLIC,
            1_800_000_000,
        );
        let nonce = 42u64;

        // Verbatim from process_update_did / check_tx.
        let handler_message = format!(
            "UpdateDid\n{}\n{}",
            serde_json::to_string(&document).unwrap(),
            nonce
        );

        assert_eq!(
            update_did_signing_message(&document, nonce).unwrap(),
            handler_message
        );
    }

    #[test]
    fn signing_message_survives_the_bincode_wire_round_trip() {
        use willow_types::consensus::transactions::{Transaction, UpdateDidTx};

        let document = rotated_document(
            &current_document(),
            "did:willow:validator1#key-1",
            OTHER_PUBLIC,
            1_800_000_000,
        );
        let nonce = 7u64;
        let signed_message = update_did_signing_message(&document, nonce).unwrap();
        let signature_hex =
            sign_challenge(&signed_message, RFC8032_SEED, SignatureAlgorithm::Ed25519).unwrap();

        let tx = Transaction::UpdateDid(UpdateDidTx {
            did_document: document,
            signature: hex::decode(&signature_hex).unwrap(),
            public_key_id: "did:willow:validator1#key-1".to_string(),
            nonce,
        });

        // What the validator actually receives and decodes.
        let decoded: Transaction = bincode::deserialize(&bincode::serialize(&tx).unwrap()).unwrap();
        let Transaction::UpdateDid(decoded_tx) = decoded else {
            panic!("bincode round trip changed the transaction variant");
        };

        let handler_message = format!(
            "UpdateDid\n{}\n{}",
            serde_json::to_string(&decoded_tx.did_document).unwrap(),
            decoded_tx.nonce
        );
        assert_eq!(handler_message, signed_message);

        // And the signature the tool produced verifies against that message.
        assert!(verify_signature(
            &handler_message,
            &hex::encode(&decoded_tx.signature),
            RFC8032_PUBLIC,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap());
    }

    #[test]
    fn signing_message_is_stable_for_a_pinned_document() {
        // Golden vector. A field rename, reorder, or serde attribute change in
        // willow-types moves these bytes and breaks every signature the chain
        // would accept — this test is the tripwire.
        let document = DidDocument {
            id: "did:willow:validator1".to_string(),
            public_keys: vec![PublicKey {
                id: "did:willow:validator1#key-1".to_string(),
                key_type: ED25519_VERIFICATION_KEY_2018.to_string(),
                controller: "did:willow:validator1".to_string(),
                public_key_base58: None,
                public_key_hex: Some(OTHER_PUBLIC.to_string()),
            }],
            authentication: vec!["did:willow:validator1#key-1".to_string()],
            service: vec![],
            created: 1,
            updated: 2,
            proof: None,
        };

        let expected = concat!(
            "UpdateDid\n",
            r#"{"id":"did:willow:validator1","public_keys":[{"id":"did:willow:validator1#key-1","#,
            r#""type":"Ed25519VerificationKey2018","controller":"did:willow:validator1","#,
            r#""public_key_base58":null,"public_key_hex":"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"}],"#,
            r#""authentication":["did:willow:validator1#key-1"],"service":[],"created":1,"updated":2,"proof":null}"#,
            "\n3",
        );
        assert_eq!(update_did_signing_message(&document, 3).unwrap(), expected);
    }

    // ========================================================================
    // Replacement document derivation
    // ========================================================================

    #[test]
    fn rotated_document_preserves_id_services_and_created() {
        let current = current_document();
        let new_doc = rotated_document(
            &current,
            "did:willow:validator1#key-1",
            OTHER_PUBLIC,
            1_800_000_000,
        );

        assert_eq!(new_doc.id, current.id);
        assert_eq!(new_doc.created, current.created);
        assert_eq!(new_doc.service.len(), 1);
        assert_eq!(new_doc.service[0].id, current.service[0].id);
        assert_eq!(
            new_doc.service[0].service_endpoint,
            current.service[0].service_endpoint
        );
    }

    #[test]
    fn rotated_document_replaces_the_key_and_bumps_updated() {
        let current = current_document();
        let new_doc = rotated_document(
            &current,
            "did:willow:validator1#key-2",
            OTHER_PUBLIC,
            1_800_000_000,
        );

        assert_eq!(new_doc.public_keys.len(), 1);
        assert_eq!(new_doc.public_keys[0].id, "did:willow:validator1#key-2");
        assert_eq!(
            new_doc.public_keys[0].public_key_hex.as_deref(),
            Some(OTHER_PUBLIC)
        );
        assert_eq!(new_doc.authentication, vec!["did:willow:validator1#key-2"]);
        assert_eq!(new_doc.updated, 1_800_000_000);
        // The published RFC test vector is gone.
        assert!(!serde_json::to_string(&new_doc)
            .unwrap()
            .contains(RFC8032_PUBLIC));
    }

    // ========================================================================
    // Anti-brick gate
    // ========================================================================

    #[test]
    fn gate_accepts_a_document_backed_by_the_held_key() {
        let new_doc = rotated_document(
            &current_document(),
            "did:willow:validator1#key-1",
            OTHER_PUBLIC,
            1_800_000_000,
        );
        assert_eq!(
            assert_key_controls_document(&new_doc, OTHER_SEED).unwrap(),
            "did:willow:validator1#key-1"
        );
    }

    #[test]
    fn gate_accepts_a_base58_encoded_public_key() {
        let mut new_doc = rotated_document(
            &current_document(),
            "did:willow:validator1#key-1",
            OTHER_PUBLIC,
            1_800_000_000,
        );
        new_doc.public_keys[0].public_key_hex = None;
        new_doc.public_keys[0].public_key_base58 =
            Some(bs58::encode(hex::decode(OTHER_PUBLIC).unwrap()).into_string());

        assert!(assert_key_controls_document(&new_doc, OTHER_SEED).is_ok());
    }

    #[test]
    fn gate_rejects_a_document_whose_authentication_key_is_not_ours() {
        // Document names TEST 2's public key; we hold TEST 1's seed.
        let new_doc = rotated_document(
            &current_document(),
            "did:willow:validator1#key-1",
            OTHER_PUBLIC,
            1_800_000_000,
        );
        let err = assert_key_controls_document(&new_doc, RFC8032_SEED).unwrap_err();
        assert!(
            err.to_string().contains("verify a probe"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn gate_rejects_an_empty_authentication_set() {
        let mut new_doc = rotated_document(
            &current_document(),
            "did:willow:validator1#key-1",
            OTHER_PUBLIC,
            1_800_000_000,
        );
        new_doc.authentication.clear();

        let err = assert_key_controls_document(&new_doc, OTHER_SEED).unwrap_err();
        assert!(
            err.to_string().contains("empty authentication set"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn gate_rejects_an_authentication_id_with_no_matching_public_key() {
        let mut new_doc = rotated_document(
            &current_document(),
            "did:willow:validator1#key-1",
            OTHER_PUBLIC,
            1_800_000_000,
        );
        new_doc
            .authentication
            .push("did:willow:validator1#ghost".to_string());

        let err = assert_key_controls_document(&new_doc, OTHER_SEED).unwrap_err();
        assert!(
            err.to_string().contains("not in public_keys"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn gate_rejects_a_public_key_with_no_key_material() {
        let mut new_doc = rotated_document(
            &current_document(),
            "did:willow:validator1#key-1",
            OTHER_PUBLIC,
            1_800_000_000,
        );
        new_doc.public_keys[0].public_key_hex = None;

        assert!(assert_key_controls_document(&new_doc, OTHER_SEED).is_err());
    }

    // ========================================================================
    // Key file handling
    // ========================================================================

    #[test]
    fn write_new_key_file_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator1.new.key");

        write_new_key_file(&path, OTHER_SEED).unwrap();
        let err = write_new_key_file(&path, RFC8032_SEED).unwrap_err();
        assert!(
            err.to_string().contains("refusing to overwrite"),
            "unexpected error: {}",
            err
        );
        // The first key is untouched.
        assert_eq!(read_key_file(&path).unwrap(), OTHER_SEED);
    }

    #[cfg(unix)]
    #[test]
    fn write_new_key_file_creates_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validator1.new.key");
        write_new_key_file(&path, OTHER_SEED).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "key file mode was {:o}", mode);
    }

    #[test]
    fn read_key_file_rejects_a_file_that_is_not_a_32_byte_seed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("truncated.key");
        write_new_key_file(&path, "deadbeef").unwrap();

        assert!(read_key_file(&path).is_err());
    }

    #[test]
    fn parse_ed25519_seed_matches_the_rfc_vector() {
        let key = parse_ed25519_seed(RFC8032_SEED).unwrap();
        assert_eq!(hex::encode(key.verifying_key().as_bytes()), RFC8032_PUBLIC);
        // 0x prefix tolerated, same as the chain's hex handling.
        let prefixed = parse_ed25519_seed(&format!("0x{}", RFC8032_SEED)).unwrap();
        assert_eq!(prefixed.to_bytes(), key.to_bytes());
    }
}
