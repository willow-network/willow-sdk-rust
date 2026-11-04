//! The messages transactions are signed over.
//!
//! Each (but a key revoke's, which joins its fields with `:`) is a set of lines joined by `\n`
//! (the byte 0x0A) with no trailing newline: the kind, then one `Label: value` line per field
//! the transaction writes, the nonce last. Text fields go in verbatim as UTF-8. Variable-length
//! bytes appear as the lowercase hex SHA-256 of the exact bytes the transaction carries, or, for
//! a key grant's keys, as their lowercase hex. Each builder reads the transaction it signs, so
//! build the message after the nonce is chosen.
//!
//! A subgrove registration signs `Subgrove`, `Owner`, `Config`, and `Nonce`, where `Config` is
//! the SHA-256 of the whole [`RegisterSubgroveTx`]'s bincode (bincode 1.x default) with an empty
//! signature ([`register_subgrove_config`]), so every field and mode setting is bound. The
//! builders for key grants, key rotations, and storage-node removals are the node's own, from
//! `willow_types::consensus::signed_messages`.
//!
//! A text field holding the byte 0x0A is refused, as the node refuses it. A write the node
//! refuses in its block after its signature and nonce verify still spends its nonce, so a retry
//! signs again under the next free nonce.

use crate::errors::{Result, WillowError};
use sha2::{Digest, Sha256};
use willow_types::consensus::signed_messages as forms;

pub use willow_types::consensus::transactions::{
    DeleteDataTx, DeleteFileManifestTx, GrantSubgroveKeyTx, RegisterSubgroveTx,
    RevokeSubgroveKeyTx, RotateSubgroveKeyTx, StoreDataTx, StoreFileManifestTx,
    UnregisterStorageNodeTx, UpdateDataTx,
};

fn field(label: &str, value: &str) -> Result<String> {
    if value.contains('\n') {
        return Err(WillowError::Validation(format!(
            "{label} holds a line break, which a signed field can't"
        )));
    }
    Ok(format!("{label}: {value}"))
}

/// `StoreData`, `Subgrove`, `Key`, `Owner`, `DataHash` (SHA-256 of `data`), `Nonce`.
pub fn store_data(tx: &StoreDataTx) -> Result<String> {
    data_write(
        "StoreData",
        &tx.subgrove_id,
        &tx.key,
        &tx.owner_did,
        &tx.data,
        tx.nonce,
    )
}

/// `UpdateData`, `Subgrove`, `Key`, `Owner`, `DataHash` (SHA-256 of `data`), `Nonce`.
pub fn update_data(tx: &UpdateDataTx) -> Result<String> {
    data_write(
        "UpdateData",
        &tx.subgrove_id,
        &tx.key,
        &tx.owner_did,
        &tx.data,
        tx.nonce,
    )
}

fn data_write(
    kind: &str,
    subgrove_id: &str,
    key: &str,
    owner_did: &str,
    data: &[u8],
    nonce: u64,
) -> Result<String> {
    Ok([
        kind.to_string(),
        field("Subgrove", subgrove_id)?,
        field("Key", key)?,
        field("Owner", owner_did)?,
        format!("DataHash: {}", hex::encode(Sha256::digest(data))),
        format!("Nonce: {nonce}"),
    ]
    .join("\n"))
}

/// `DeleteData`, `Subgrove`, `Key`, `Owner`, `Nonce`.
pub fn delete_data(tx: &DeleteDataTx) -> Result<String> {
    Ok([
        "DeleteData".to_string(),
        field("Subgrove", &tx.subgrove_id)?,
        field("Key", &tx.key)?,
        field("Owner", &tx.owner_did)?,
        format!("Nonce: {}", tx.nonce),
    ]
    .join("\n"))
}

/// `StoreFileManifest` and every manifest field. `Encryption` is `none`, or the key epoch and
/// the hex XChaCha20 nonce joined by `:`.
pub fn store_file_manifest(tx: &StoreFileManifestTx) -> Result<String> {
    let encryption = match &tx.encryption {
        None => "none".to_string(),
        Some(e) => format!("{}:{}", e.key_epoch, hex::encode(e.nonce)),
    };
    Ok([
        "StoreFileManifest".to_string(),
        field("Subgrove", &tx.subgrove_id)?,
        field("Key", &tx.file_key)?,
        field("Owner", &tx.owner_did)?,
        field("Filename", &tx.filename)?,
        field("ContentType", &tx.content_type)?,
        format!("TotalSize: {}", tx.total_size),
        format!("ContentHash: {}", hex::encode(tx.content_hash)),
        format!("ChunkCount: {}", tx.chunk_count),
        format!("ChunkSize: {}", tx.chunk_size),
        format!("ChunkMerkleRoot: {}", hex::encode(tx.chunk_merkle_root)),
        format!("Encryption: {encryption}"),
        format!("Nonce: {}", tx.nonce),
    ]
    .join("\n"))
}

/// `DeleteFileManifest`, `Subgrove`, `Key`, `Owner`, `Nonce`.
pub fn delete_file_manifest(tx: &DeleteFileManifestTx) -> Result<String> {
    Ok([
        "DeleteFileManifest".to_string(),
        field("Subgrove", &tx.subgrove_id)?,
        field("Key", &tx.file_key)?,
        field("Owner", &tx.owner_did)?,
        format!("Nonce: {}", tx.nonce),
    ]
    .join("\n"))
}

/// The bincode (1.x default) of `tx` with an empty signature: the bytes a registration's
/// `Config` hashes. Every other field is encoded as sent, so build `tx` with every field it will
/// carry.
pub fn register_subgrove_unsigned_bincode(tx: &RegisterSubgroveTx) -> Result<Vec<u8>> {
    let unsigned = RegisterSubgroveTx {
        signature: Vec::new(),
        ..tx.clone()
    };
    bincode::serialize(&unsigned)
        .map_err(|e| WillowError::Custom(format!("Failed to encode the registration: {e}")))
}

/// The SHA-256 of [`register_subgrove_unsigned_bincode`].
pub fn register_subgrove_config(tx: &RegisterSubgroveTx) -> Result<[u8; 32]> {
    Ok(Sha256::digest(register_subgrove_unsigned_bincode(tx)?).into())
}

/// `RegisterSubgrove`, `Subgrove`, `Owner`, `Config` ([`register_subgrove_config`], lowercase
/// hex), `Nonce`. Every mode is signed this way.
pub fn register_subgrove(tx: &RegisterSubgroveTx) -> Result<String> {
    Ok([
        "RegisterSubgrove".to_string(),
        field("Subgrove", &tx.subgrove_id)?,
        field("Owner", &tx.owner_did)?,
        format!("Config: {}", hex::encode(register_subgrove_config(tx)?)),
        format!("Nonce: {}", tx.nonce),
    ]
    .join("\n"))
}

/// `GrantSubgroveKey`, `Subgrove`, `Sender`, then every field of the grant (`Grantee`,
/// `GranteeKey`, `KeyEpoch`, `EphemeralKey` and `EncryptedKey` as lowercase hex, `GrantedBy`,
/// `GrantedAt`), `Nonce`.
pub fn grant_subgrove_key(tx: &GrantSubgroveKeyTx) -> Result<String> {
    forms::grant_subgrove_key(tx).map_err(WillowError::Validation)
}

/// `RotateSubgroveKey`, `Subgrove`, `Sender`, `NewEpoch`, `Grants` (the count), each grant's
/// seven lines in order (as in [`grant_subgrove_key`]), `Nonce`.
pub fn rotate_subgrove_key(tx: &RotateSubgroveKeyTx) -> Result<String> {
    forms::rotate_subgrove_key(tx).map_err(WillowError::Validation)
}

/// `RevokeSubgroveKey:{subgrove_id}:{revokee_did}:{sender_did}:{nonce}`. It binds every field;
/// a subgrove ID holding `:`, or a revokee or sender that isn't a `did:willow:` DID of letters,
/// digits, `-`, and `_`, is refused, as the node refuses it, so the message splits one way.
pub fn revoke_subgrove_key(tx: &RevokeSubgroveKeyTx) -> Result<String> {
    if tx.subgrove_id.contains(':') {
        return Err(WillowError::Validation(
            "Subgrove holds ':', which a revoke's subgrove ID can't".to_string(),
        ));
    }
    validate_did(&tx.revokee_did, "revokee_did")?;
    validate_did(&tx.sender_did, "sender_did")?;
    Ok(format!(
        "RevokeSubgroveKey:{}:{}:{}:{}",
        tx.subgrove_id, tx.revokee_did, tx.sender_did, tx.nonce
    ))
}

/// `UnregisterStorageNode`, `Node`, `Nonce`.
pub fn unregister_storage_node(tx: &UnregisterStorageNodeTx) -> Result<String> {
    forms::unregister_storage_node(tx).map_err(WillowError::Validation)
}

fn validate_did(did: &str, label: &str) -> Result<()> {
    willow_types::consensus::transactions::validate_did(did, label).map_err(WillowError::Validation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::sign_challenge;
    use crate::client::WillowClient;
    use crate::consensus::ConsensusClient;
    use crate::subgrove_config::SubgroveDefinition;
    use crate::types::{RegisterSubgroveRequest, SignatureAlgorithm, StoreDataRequest};
    use base64::Engine;
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use serde_json::json;
    use sha3::Keccak256;
    use willow_types::consensus::indexing_transactions::SubgroveMode;
    use willow_types::consensus::transactions::Transaction;
    use willow_types::storage::{EncryptedKeyGrant, FileEncryption};
    use wiremock::matchers::{body_partial_json, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SEED_HEX: &str = "0303030303030303030303030303030303030303030303030303030303030303";
    const OWNER: &str = "did:willow:a";
    const KEY_ID: &str = "did:willow:a#key-1";

    fn seed_key() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    fn store() -> StoreDataTx {
        StoreDataTx {
            subgrove_id: "sg-1".into(),
            key: "doc1".into(),
            data: br#"{"title":"Hello","value":42}"#.to_vec(),
            owner_did: OWNER.into(),
            signature: vec![],
            public_key_id: KEY_ID.into(),
            nonce: 7,
        }
    }

    fn update() -> UpdateDataTx {
        UpdateDataTx {
            subgrove_id: "sg-1".into(),
            key: "doc1".into(),
            data: b"{}".to_vec(),
            owner_did: OWNER.into(),
            signature: vec![],
            public_key_id: KEY_ID.into(),
            nonce: 8,
        }
    }

    fn delete() -> DeleteDataTx {
        DeleteDataTx {
            subgrove_id: "sg-1".into(),
            key: "doc1".into(),
            owner_did: OWNER.into(),
            signature: vec![],
            public_key_id: KEY_ID.into(),
            nonce: 10,
        }
    }

    fn manifest() -> StoreFileManifestTx {
        StoreFileManifestTx {
            subgrove_id: "files-1".into(),
            file_key: "photo.png".into(),
            filename: "photo.png".into(),
            content_type: "image/png".into(),
            total_size: 1_048_577,
            content_hash: [0x11; 32],
            chunk_count: 2,
            chunk_size: 1_048_576,
            chunk_merkle_root: [0x22; 32],
            owner_did: OWNER.into(),
            encryption: None,
            signature: vec![],
            public_key_id: KEY_ID.into(),
            nonce: 9,
        }
    }

    fn delete_file() -> DeleteFileManifestTx {
        DeleteFileManifestTx {
            subgrove_id: "files-1".into(),
            file_key: "photo.png".into(),
            owner_did: OWNER.into(),
            signature: vec![],
            public_key_id: KEY_ID.into(),
            nonce: 11,
        }
    }

    /// The shared known answers: each message byte for byte, and its Ed25519 and secp256k1
    /// signatures under seed `03` x 32.
    #[test]
    fn the_messages_are_the_known_answers() {
        let kat: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/signed_messages_kat.json"))
                .unwrap();
        assert_eq!(kat["private_key_seed_hex"], SEED_HEX);
        assert_eq!(kat["public_key_id"], KEY_ID);
        assert_eq!(
            hex::encode(seed_key().verifying_key().to_bytes()),
            kat["ed25519_public_key_hex"].as_str().unwrap()
        );
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[3; 32]).unwrap();
        assert_eq!(
            hex::encode(secp256k1::PublicKey::from_secret_key(&secp, &secret).serialize()),
            kat["secp256k1_public_key_compressed_hex"].as_str().unwrap()
        );

        let hex32 = |v: &serde_json::Value| -> [u8; 32] {
            hex::decode(v.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let vectors = kat["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 7);
        for v in vectors {
            let name = v["name"].as_str().unwrap();
            let i = &v["inputs"];
            let s = |k: &str| i[k].as_str().unwrap().to_string();
            let n = |k: &str| i[k].as_u64().unwrap();
            let message = match name {
                "StoreData" | "StoreData (non-ASCII, large nonce)" => store_data(&StoreDataTx {
                    subgrove_id: s("subgrove_id"),
                    key: s("key"),
                    data: s("data_utf8").into_bytes(),
                    owner_did: s("owner_did"),
                    nonce: n("nonce"),
                    ..store()
                }),
                "UpdateData" => update_data(&UpdateDataTx {
                    subgrove_id: s("subgrove_id"),
                    key: s("key"),
                    data: s("data_utf8").into_bytes(),
                    owner_did: s("owner_did"),
                    nonce: n("nonce"),
                    ..update()
                }),
                "DeleteData" => delete_data(&DeleteDataTx {
                    subgrove_id: s("subgrove_id"),
                    key: s("key"),
                    owner_did: s("owner_did"),
                    nonce: n("nonce"),
                    ..delete()
                }),
                "StoreFileManifest" | "StoreFileManifest (encrypted)" => {
                    store_file_manifest(&StoreFileManifestTx {
                        subgrove_id: s("subgrove_id"),
                        file_key: s("file_key"),
                        filename: s("filename"),
                        content_type: s("content_type"),
                        total_size: n("total_size"),
                        content_hash: hex32(&i["content_hash_hex"]),
                        chunk_count: n("chunk_count").try_into().unwrap(),
                        chunk_size: n("chunk_size").try_into().unwrap(),
                        chunk_merkle_root: hex32(&i["chunk_merkle_root_hex"]),
                        owner_did: s("owner_did"),
                        encryption: i["encryption"].as_object().map(|e| FileEncryption {
                            key_epoch: e["key_epoch"].as_u64().unwrap(),
                            nonce: hex::decode(e["nonce_hex"].as_str().unwrap())
                                .unwrap()
                                .try_into()
                                .unwrap(),
                        }),
                        nonce: n("nonce"),
                        ..manifest()
                    })
                }
                "DeleteFileManifest" => delete_file_manifest(&DeleteFileManifestTx {
                    subgrove_id: s("subgrove_id"),
                    file_key: s("file_key"),
                    owner_did: s("owner_did"),
                    nonce: n("nonce"),
                    ..delete_file()
                }),
                other => panic!("unknown vector {other}"),
            }
            .unwrap();
            assert_eq!(message, v["message"].as_str().unwrap(), "{name}");

            assert_eq!(
                hex::encode(seed_key().sign(message.as_bytes()).to_bytes()),
                v["ed25519_signature_hex"].as_str().unwrap(),
                "{name} Ed25519"
            );
            assert_eq!(
                sign_challenge(&message, SEED_HEX, SignatureAlgorithm::Ed25519).unwrap(),
                v["ed25519_signature_hex"].as_str().unwrap(),
                "{name} Ed25519 via sign_challenge"
            );
            assert_eq!(
                hex::encode(Keccak256::digest(message.as_bytes())),
                v["secp256k1_keccak256_hex"].as_str().unwrap(),
                "{name} Keccak-256"
            );
            assert_eq!(
                sign_challenge(&message, SEED_HEX, SignatureAlgorithm::Secp256k1).unwrap(),
                v["secp256k1_compact_signature_hex"].as_str().unwrap(),
                "{name} secp256k1"
            );
        }
    }

    #[test]
    fn a_signed_text_field_with_a_line_break_is_refused() {
        fn refused(result: Result<String>, label: &str) {
            match result {
                Err(WillowError::Validation(e)) => {
                    assert!(e.starts_with(&format!("{label} holds a line break")), "{e}")
                }
                other => panic!("{label}: expected a refusal, got {other:?}"),
            }
        }
        let broken = "a\nKey: b".to_string();

        refused(
            store_data(&StoreDataTx {
                subgrove_id: broken.clone(),
                ..store()
            }),
            "Subgrove",
        );
        refused(
            store_data(&StoreDataTx {
                key: broken.clone(),
                ..store()
            }),
            "Key",
        );
        refused(
            store_data(&StoreDataTx {
                owner_did: broken.clone(),
                ..store()
            }),
            "Owner",
        );
        refused(
            update_data(&UpdateDataTx {
                key: broken.clone(),
                ..update()
            }),
            "Key",
        );
        refused(
            delete_data(&DeleteDataTx {
                subgrove_id: broken.clone(),
                ..delete()
            }),
            "Subgrove",
        );
        refused(
            delete_data(&DeleteDataTx {
                key: broken.clone(),
                ..delete()
            }),
            "Key",
        );
        refused(
            delete_data(&DeleteDataTx {
                owner_did: broken.clone(),
                ..delete()
            }),
            "Owner",
        );
        for (tx, label) in [
            (
                StoreFileManifestTx {
                    subgrove_id: broken.clone(),
                    ..manifest()
                },
                "Subgrove",
            ),
            (
                StoreFileManifestTx {
                    file_key: broken.clone(),
                    ..manifest()
                },
                "Key",
            ),
            (
                StoreFileManifestTx {
                    owner_did: broken.clone(),
                    ..manifest()
                },
                "Owner",
            ),
            (
                StoreFileManifestTx {
                    filename: broken.clone(),
                    ..manifest()
                },
                "Filename",
            ),
            (
                StoreFileManifestTx {
                    content_type: broken.clone(),
                    ..manifest()
                },
                "ContentType",
            ),
        ] {
            refused(store_file_manifest(&tx), label);
        }
        refused(
            delete_file_manifest(&DeleteFileManifestTx {
                file_key: broken.clone(),
                ..delete_file()
            }),
            "Key",
        );

        // Only 0x0A is refused; a carriage return goes in verbatim.
        assert_eq!(
            delete_data(&DeleteDataTx {
                key: "a\rb".into(),
                ..delete()
            })
            .unwrap(),
            "DeleteData\nSubgrove: sg-1\nKey: a\rb\nOwner: did:willow:a\nNonce: 10"
        );

        // Data is hashed, so a line break in it is signed like any other byte.
        assert!(store_data(&StoreDataTx {
            data: b"\"a\\nb\"\n".to_vec(),
            ..store()
        })
        .is_ok());
    }

    /// An API and CometBFT RPC that hand out `base + 1` as the next nonce, accept every tx,
    /// report it in a block, and take every chunk.
    async fn mock_chain(base: u64) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/account/[^/]+/nonce$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"success": true, "data": {"nonce": base}})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "broadcast_tx_sync"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {"code": 0, "data": "", "log": "", "hash": "ABCD"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "tx"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {"height": "5", "tx_result": {"code": 0, "log": ""}}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/upload/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        server
    }

    /// Every transaction broadcast to `server`, decoded from the bincode the node reads, as the
    /// node decodes it (bincode 1.x default, refusing bytes after the transaction).
    async fn broadcast(server: &MockServer) -> Vec<Transaction> {
        use bincode::Options;
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter_map(|r| r.body_json::<serde_json::Value>().ok())
            .filter(|b| b["method"] == "broadcast_tx_sync")
            .map(|b| {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b["params"]["tx"].as_str().unwrap())
                    .unwrap();
                let tx: Transaction = bincode::DefaultOptions::new()
                    .with_fixint_encoding()
                    .reject_trailing_bytes()
                    .deserialize(&bytes)
                    .unwrap();
                assert_eq!(bincode::serialize(&tx).unwrap(), bytes);
                tx
            })
            .collect()
    }

    fn assert_signed(message: &str, signature: &[u8]) {
        let signature = Signature::from_slice(signature).unwrap();
        seed_key()
            .verifying_key()
            .verify_strict(message.as_bytes(), &signature)
            .unwrap_or_else(|e| panic!("signature does not verify over {message:?}: {e}"));
    }

    async fn file_client(server: &MockServer) -> WillowClient {
        let client = WillowClient::builder()
            .api_url(&server.uri())
            .consensus_url(&server.uri())
            .build()
            .await
            .unwrap();
        client.set_identity_with_algorithm(OWNER, SEED_HEX, KEY_ID, SignatureAlgorithm::Ed25519);
        client
    }

    #[tokio::test]
    async fn store_data_sends_a_tx_signed_over_its_own_fields_and_nonce() {
        let server = mock_chain(6).await;
        let consensus = ConsensusClient::new_with_api(&server.uri(), &server.uri());
        let request = StoreDataRequest {
            subgrove_id: "sg-1".into(),
            key: "doc1".into(),
            data: json!({"title": "Hello", "value": 42}),
            owner_did: OWNER.into(),
            signature: vec![],
            public_key_id: KEY_ID.into(),
            nonce: 0,
        };
        consensus.store_data(request, &seed_key()).await.unwrap();

        let sent = broadcast(&server).await;
        let [Transaction::StoreData(tx)] = sent.as_slice() else {
            panic!("expected one StoreData, got {sent:?}");
        };
        assert_eq!(tx.nonce, 7);
        assert_eq!(tx.data, br#"{"title":"Hello","value":42}"#);
        let message = format!(
            "StoreData\nSubgrove: {}\nKey: {}\nOwner: {}\nDataHash: {}\nNonce: {}",
            tx.subgrove_id,
            tx.key,
            tx.owner_did,
            hex::encode(Sha256::digest(&tx.data)),
            tx.nonce
        );
        assert_signed(&message, &tx.signature);
    }

    #[tokio::test]
    async fn store_data_refuses_a_key_with_a_line_break_and_sends_nothing() {
        let server = mock_chain(6).await;
        let consensus = ConsensusClient::new_with_api(&server.uri(), &server.uri());
        let request = StoreDataRequest {
            subgrove_id: "sg-1".into(),
            key: "doc1\nKey: doc2".into(),
            data: json!({}),
            owner_did: OWNER.into(),
            signature: vec![],
            public_key_id: KEY_ID.into(),
            nonce: 0,
        };
        let err = consensus
            .store_data(request, &seed_key())
            .await
            .unwrap_err();
        assert!(matches!(err, WillowError::Validation(_)), "{err}");
        assert!(broadcast(&server).await.is_empty());
    }

    #[tokio::test]
    async fn delete_data_sends_a_tx_signed_over_its_own_fields_and_nonce() {
        let server = mock_chain(9).await;
        let consensus = ConsensusClient::new_with_api(&server.uri(), &server.uri());
        consensus
            .delete_data("sg-1", "doc1", OWNER, KEY_ID, &seed_key())
            .await
            .unwrap();

        let sent = broadcast(&server).await;
        let [Transaction::DeleteData(tx)] = sent.as_slice() else {
            panic!("expected one DeleteData, got {sent:?}");
        };
        assert_eq!(tx.nonce, 10);
        let message = format!(
            "DeleteData\nSubgrove: {}\nKey: {}\nOwner: {}\nNonce: {}",
            tx.subgrove_id, tx.key, tx.owner_did, tx.nonce
        );
        assert_signed(&message, &tx.signature);
    }

    #[tokio::test]
    async fn a_file_upload_signs_every_manifest_field_and_its_nonce() {
        let server = mock_chain(8).await;
        let client = file_client(&server).await;
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        client
            .files()
            .upload(
                "files-1",
                "photo.png",
                "photo.png",
                &data,
                &server.uri(),
                Some(&seed_key()),
                Some(KEY_ID),
            )
            .await
            .unwrap();

        let sent = broadcast(&server).await;
        let [Transaction::StoreFileManifest(tx)] = sent.as_slice() else {
            panic!("expected one StoreFileManifest, got {sent:?}");
        };
        assert_eq!(tx.nonce, 9);
        assert_eq!(tx.content_hash, <[u8; 32]>::from(Sha256::digest(&data)));
        assert_eq!(tx.total_size, data.len() as u64);
        assert_eq!(tx.chunk_count, 2);
        assert_eq!(tx.content_type, "image/png");
        assert!(tx.encryption.is_none());
        let message = format!(
            "StoreFileManifest\nSubgrove: {}\nKey: {}\nOwner: {}\nFilename: {}\nContentType: {}\n\
             TotalSize: {}\nContentHash: {}\nChunkCount: {}\nChunkSize: {}\nChunkMerkleRoot: {}\n\
             Encryption: none\nNonce: {}",
            tx.subgrove_id,
            tx.file_key,
            tx.owner_did,
            tx.filename,
            tx.content_type,
            tx.total_size,
            hex::encode(tx.content_hash),
            tx.chunk_count,
            tx.chunk_size,
            hex::encode(tx.chunk_merkle_root),
            tx.nonce
        );
        assert_signed(&message, &tx.signature);
    }

    #[tokio::test]
    async fn a_file_delete_signs_its_fields_and_nonce() {
        let server = mock_chain(10).await;
        let client = file_client(&server).await;
        client
            .files()
            .delete("files-1", "photo.png", Some(&seed_key()), Some(KEY_ID))
            .await
            .unwrap();

        let sent = broadcast(&server).await;
        let [Transaction::DeleteFileManifest(tx)] = sent.as_slice() else {
            panic!("expected one DeleteFileManifest, got {sent:?}");
        };
        assert_eq!(tx.nonce, 11);
        let message = format!(
            "DeleteFileManifest\nSubgrove: {}\nKey: {}\nOwner: {}\nNonce: {}",
            tx.subgrove_id, tx.file_key, tx.owner_did, tx.nonce
        );
        assert_signed(&message, &tx.signature);
    }

    /// The second set's shared known answers: for every kind the SDK sends, the message byte for
    /// byte, a registration's unsigned bincode, and the Ed25519 and secp256k1 signatures under
    /// seed `03` x 32. Each transaction is parsed from its exact `/tx/submit` JSON, big integers
    /// included.
    #[test]
    fn the_second_set_is_the_known_answers() {
        let kat: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/signed_messages_kat_2.json"))
                .unwrap();
        assert_eq!(kat["private_key_seed_hex"], SEED_HEX);
        assert_eq!(kat["public_key_id"], KEY_ID);
        assert_eq!(
            hex::encode(seed_key().verifying_key().to_bytes()),
            kat["ed25519_public_key_hex"].as_str().unwrap()
        );

        let mut signed = vec![];
        let mut not_sent = vec![];
        for v in kat["vectors"].as_array().unwrap() {
            let name = v["name"].as_str().unwrap();
            let tx: Transaction =
                serde_json::from_str(v["transaction_json"].as_str().unwrap()).unwrap();
            let (message, unsigned) = match &tx {
                Transaction::RegisterSubgrove(t) => {
                    assert!(t.signature.is_empty(), "{name}");
                    (
                        register_subgrove(t),
                        Some(register_subgrove_unsigned_bincode(t).unwrap()),
                    )
                }
                Transaction::GrantSubgroveKey(t) => (grant_subgrove_key(t), None),
                Transaction::RotateSubgroveKey(t) => (rotate_subgrove_key(t), None),
                Transaction::UnregisterStorageNode(t) => (unregister_storage_node(t), None),
                // Kinds this SDK doesn't send.
                Transaction::UpdateSubgroveReadPricing(_)
                | Transaction::BlockContentHash(_)
                | Transaction::UnblockContentHash(_)
                | Transaction::ReportContent(_) => {
                    not_sent.push(name);
                    continue;
                }
                other => panic!("unexpected vector {name}: {other:?}"),
            };
            let message = message.unwrap();
            assert_eq!(message, v["message"].as_str().unwrap(), "{name}");
            match unsigned {
                Some(bytes) => assert_eq!(
                    hex::encode(bytes),
                    v["unsigned_bincode_hex"].as_str().unwrap(),
                    "{name} unsigned bincode"
                ),
                None => assert!(v["unsigned_bincode_hex"].is_null(), "{name}"),
            }
            assert_eq!(
                hex::encode(seed_key().sign(message.as_bytes()).to_bytes()),
                v["ed25519_signature_hex"].as_str().unwrap(),
                "{name} Ed25519"
            );
            assert_eq!(
                hex::encode(Keccak256::digest(message.as_bytes())),
                v["secp256k1_keccak256_hex"].as_str().unwrap(),
                "{name} Keccak-256"
            );
            assert_eq!(
                sign_challenge(&message, SEED_HEX, SignatureAlgorithm::Secp256k1).unwrap(),
                v["secp256k1_compact_signature_hex"].as_str().unwrap(),
                "{name} secp256k1"
            );
            signed.push(name);
        }
        assert_eq!(signed.len(), 8, "{signed:?}");
        assert_eq!(not_sent.len(), 5, "{not_sent:?}");
    }

    /// A registration's bincode is the node's: the transaction broadcast is the variant index
    /// then the struct, which the node decodes with nothing left over.
    #[test]
    fn a_registration_encodes_every_field_the_node_decodes() {
        use bincode::Options;
        let kat: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/signed_messages_kat_2.json"))
                .unwrap();
        for v in kat["vectors"].as_array().unwrap() {
            let tx: Transaction =
                serde_json::from_str(v["transaction_json"].as_str().unwrap()).unwrap();
            let Transaction::RegisterSubgrove(t) = &tx else {
                continue;
            };
            let bytes = bincode::serialize(&tx).unwrap();
            assert_eq!(
                hex::encode(&bytes[4..]),
                v["unsigned_bincode_hex"].as_str().unwrap()
            );
            // The last field is `cryptographic_completeness`, one byte.
            assert_eq!(*bytes.last().unwrap(), t.cryptographic_completeness as u8);
            let back: Transaction = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .reject_trailing_bytes()
                .deserialize(&bytes)
                .unwrap();
            assert_eq!(bincode::serialize(&back).unwrap(), bytes);
        }
    }

    fn registration() -> RegisterSubgroveTx {
        RegisterSubgroveTx {
            subgrove_id: "sg-1".into(),
            name: "Notes".into(),
            description: String::new(),
            schema: "{}".into(),
            owner_did: OWNER.into(),
            admins: vec![],
            initial_funding: None,
            checkpoint_verification: Default::default(),
            mode: SubgroveMode::DataStorage {
                name: "Notes".into(),
                writers: vec![],
                free_readers: vec![],
                read_pricing: None,
            },
            privacy: None,
            initial_owner_key_grant: None,
            template_config: None,
            confirmation_depth: 0,
            signature: vec![],
            public_key_id: KEY_ID.into(),
            nonce: 4,
            cryptographic_completeness: false,
        }
    }

    fn key_grant(grantee: &str) -> EncryptedKeyGrant {
        EncryptedKeyGrant {
            grantee_did: grantee.into(),
            key_epoch: 1,
            grantee_public_key_id: format!("{grantee}#key-1"),
            ephemeral_public_key: vec![0x50; 32],
            encrypted_key: vec![0x51; 72],
            granted_by: OWNER.into(),
            granted_at: 1_800_000_000,
        }
    }

    #[test]
    fn a_second_set_text_field_with_a_line_break_is_refused() {
        fn refused(result: Result<String>, label: &str) {
            match result {
                Err(WillowError::Validation(e)) => {
                    assert!(e.starts_with(&format!("{label} holds a line break")), "{e}")
                }
                other => panic!("{label}: expected a refusal, got {other:?}"),
            }
        }
        let broken = "a\nNonce: 1".to_string();

        refused(
            register_subgrove(&RegisterSubgroveTx {
                subgrove_id: broken.clone(),
                ..registration()
            }),
            "Subgrove",
        );
        refused(
            register_subgrove(&RegisterSubgroveTx {
                owner_did: broken.clone(),
                ..registration()
            }),
            "Owner",
        );
        // Hashed fields are bound through `Config`, so a line break in them is signed like any
        // other byte.
        assert!(register_subgrove(&RegisterSubgroveTx {
            description: broken.clone(),
            ..registration()
        })
        .is_ok());

        let grant = GrantSubgroveKeyTx {
            subgrove_id: "private-1".into(),
            encrypted_key_grant: key_grant("did:willow:b"),
            sender_did: OWNER.into(),
            signature: vec![],
            public_key_id: KEY_ID.into(),
            nonce: 5,
        };
        refused(
            grant_subgrove_key(&GrantSubgroveKeyTx {
                subgrove_id: broken.clone(),
                ..grant.clone()
            }),
            "Subgrove",
        );
        refused(
            grant_subgrove_key(&GrantSubgroveKeyTx {
                sender_did: broken.clone(),
                ..grant.clone()
            }),
            "Sender",
        );
        for (edit, label) in [(0, "Grantee"), (1, "GranteeKey"), (2, "GrantedBy")] {
            let mut g = key_grant("did:willow:b");
            match edit {
                0 => g.grantee_did = broken.clone(),
                1 => g.grantee_public_key_id = broken.clone(),
                _ => g.granted_by = broken.clone(),
            }
            refused(
                grant_subgrove_key(&GrantSubgroveKeyTx {
                    encrypted_key_grant: g.clone(),
                    ..grant.clone()
                }),
                label,
            );
            refused(
                rotate_subgrove_key(&RotateSubgroveKeyTx {
                    subgrove_id: "private-1".into(),
                    new_epoch: 2,
                    new_grants: vec![key_grant("did:willow:a"), g],
                    sender_did: OWNER.into(),
                    signature: vec![],
                    public_key_id: KEY_ID.into(),
                    nonce: 6,
                }),
                label,
            );
        }
        refused(
            unregister_storage_node(&UnregisterStorageNodeTx {
                node_did: broken,
                signature: vec![],
                public_key_id: KEY_ID.into(),
                nonce: 7,
            }),
            "Node",
        );
    }

    #[test]
    fn a_revoke_that_could_split_another_way_is_refused() {
        let revoke = RevokeSubgroveKeyTx {
            subgrove_id: "private-1".into(),
            revokee_did: "did:willow:b".into(),
            sender_did: OWNER.into(),
            signature: vec![],
            public_key_id: KEY_ID.into(),
            nonce: 8,
        };
        assert_eq!(
            revoke_subgrove_key(&revoke).unwrap(),
            "RevokeSubgroveKey:private-1:did:willow:b:did:willow:a:8"
        );
        for tx in [
            RevokeSubgroveKeyTx {
                subgrove_id: "private:1".into(),
                ..revoke.clone()
            },
            RevokeSubgroveKeyTx {
                revokee_did: "did:willow:b:did:willow:c".into(),
                ..revoke.clone()
            },
            RevokeSubgroveKeyTx {
                sender_did: "did:other:a".into(),
                ..revoke.clone()
            },
        ] {
            assert!(
                matches!(revoke_subgrove_key(&tx), Err(WillowError::Validation(_))),
                "{tx:?}"
            );
        }
    }

    /// The message a registration signs, rebuilt from the transaction's own fields.
    fn registration_message(tx: &RegisterSubgroveTx) -> String {
        let unsigned = RegisterSubgroveTx {
            signature: vec![],
            ..tx.clone()
        };
        format!(
            "RegisterSubgrove\nSubgrove: {}\nOwner: {}\nConfig: {}\nNonce: {}",
            tx.subgrove_id,
            tx.owner_did,
            hex::encode(Sha256::digest(bincode::serialize(&unsigned).unwrap())),
            tx.nonce
        )
    }

    /// The one RegisterSubgrove broadcast to `server`.
    async fn sent_registration(server: &MockServer) -> RegisterSubgroveTx {
        let sent = broadcast(server).await;
        let [Transaction::RegisterSubgrove(tx)] = sent.as_slice() else {
            panic!("expected one RegisterSubgrove, got {sent:?}");
        };
        tx.clone()
    }

    #[tokio::test]
    async fn register_subgrove_signs_the_config_of_the_tx_it_sends() {
        let server = mock_chain(3).await;
        let consensus = ConsensusClient::new_with_api(&server.uri(), &server.uri());
        let request = RegisterSubgroveRequest {
            subgrove_id: "notes-1".into(),
            name: "Notes".into(),
            description: "Team notes".into(),
            schema: None,
            owner_did: OWNER.into(),
            admins: vec!["did:willow:b".into()],
            initial_funding: Some(5_000_000_000_000_000_000),
            writers: vec![OWNER.into()],
            readers: vec!["did:willow:c".into()],
            signature: vec![1; 64],
            public_key_id: KEY_ID.into(),
            nonce: 99,
        };
        consensus
            .register_subgrove(request, &seed_key())
            .await
            .unwrap();

        let tx = sent_registration(&server).await;
        assert_eq!(tx.nonce, 4);
        assert_eq!(tx.initial_funding, Some(5_000_000_000_000_000_000));
        assert_eq!(tx.admins, vec!["did:willow:b".to_string()]);
        assert!(!tx.cryptographic_completeness);
        let SubgroveMode::DataStorage {
            writers,
            free_readers,
            ..
        } = &tx.mode
        else {
            panic!("expected DataStorage, got {:?}", tx.mode);
        };
        assert_eq!(writers, &vec![OWNER.to_string()]);
        assert_eq!(free_readers, &vec!["did:willow:c".to_string()]);
        assert_signed(&registration_message(&tx), &tx.signature);
    }

    #[tokio::test]
    async fn register_file_subgrove_signs_the_config_of_the_tx_it_sends() {
        let server = mock_chain(4).await;
        let consensus = ConsensusClient::new_with_api(&server.uri(), &server.uri());
        consensus
            .register_file_subgrove(
                "files-1",
                "Files",
                OWNER,
                vec![OWNER.into()],
                vec![],
                104_857_600,
                3,
                KEY_ID,
                &seed_key(),
                Some(1),
            )
            .await
            .unwrap();

        let tx = sent_registration(&server).await;
        assert_eq!(tx.nonce, 5);
        assert!(matches!(
            tx.mode,
            SubgroveMode::FileStorage {
                max_file_size: 104_857_600,
                replication_factor: 3,
                ..
            }
        ));
        assert_signed(&registration_message(&tx), &tx.signature);
    }

    #[tokio::test]
    async fn register_blockchain_subgrove_signs_the_config_of_the_tx_it_sends() {
        let server = mock_chain(5).await;
        let consensus = ConsensusClient::new_with_api(&server.uri(), &server.uri());
        let definition = SubgroveDefinition::from_toml(
            r#"
subgrove_id = "idx-1"
description = "Swaps"
execution_mode = "IndexerExecution"
sampling_rate_percent = 10
required_tee = "AwsNitro"
schema = "type Swap @entity { id: ID! }"

[manifest]
spec_version = "1.0.0"
description = "Swaps"

[[manifest.data_sources]]
name = "Pool"
network = "mainnet"
address = "0x1234567890abcdef1234567890abcdef12345678"
abi = "Pool"
start_block = 1
events = ["Swap(address,address,int256)"]
"#,
        )
        .unwrap();
        consensus
            .register_blockchain_subgrove(&definition, OWNER, KEY_ID, &seed_key(), None)
            .await
            .unwrap();

        let tx = sent_registration(&server).await;
        assert_eq!(tx.nonce, 6);
        assert_eq!(
            tx.checkpoint_verification.required_tee,
            Some(willow_types::tee::TeeType::AwsNitro)
        );
        assert!(matches!(tx.mode, SubgroveMode::BlockchainIndexing { .. }));
        let mut expected = definition
            .register_transaction(OWNER, KEY_ID, 6, None)
            .unwrap();
        expected.signature = tx.signature.clone();
        assert_eq!(
            bincode::serialize(&expected).unwrap(),
            bincode::serialize(&tx).unwrap()
        );
        assert_signed(&registration_message(&tx), &tx.signature);
    }

    #[tokio::test]
    async fn a_registration_with_a_line_break_or_unknown_mode_sends_nothing() {
        let server = mock_chain(3).await;
        let consensus = ConsensusClient::new_with_api(&server.uri(), &server.uri());
        let err = consensus
            .register_file_subgrove(
                "files-1\nOwner: did:willow:b",
                "Files",
                OWNER,
                vec![],
                vec![],
                1,
                1,
                KEY_ID,
                &seed_key(),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, WillowError::Validation(_)), "{err}");

        let mut definition = SubgroveDefinition::from_toml(
            r#"
subgrove_id = "idx-1"
description = "Swaps"
execution_mode = "GkrExecution"
schema = "type Swap @entity { id: ID! }"

[manifest]
spec_version = "1.0.0"
description = "Swaps"

[[manifest.data_sources]]
name = "Pool"
network = "mainnet"
address = "0x1234567890abcdef1234567890abcdef12345678"
abi = "Pool"
start_block = 1
events = ["Swap(address,address,int256)"]
"#,
        )
        .unwrap();
        let err = consensus
            .register_blockchain_subgrove(&definition, OWNER, KEY_ID, &seed_key(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, WillowError::Validation(_)), "{err}");
        definition.execution_mode = "ConsensusExecution".into();
        definition.required_tee = Some("Nitro".into());
        assert!(consensus
            .register_blockchain_subgrove(&definition, OWNER, KEY_ID, &seed_key(), None)
            .await
            .is_err());

        assert!(broadcast(&server).await.is_empty());
    }

    #[tokio::test]
    async fn key_grants_rotations_and_revokes_sign_every_field_and_their_nonce() {
        let server = mock_chain(0).await;
        let client = file_client(&server).await;
        let privacy = client.privacy();
        privacy
            .grant_subgrove_key(
                "private-1",
                key_grant("did:willow:b"),
                OWNER,
                &seed_key(),
                KEY_ID,
                21,
            )
            .await
            .unwrap();
        privacy
            .rotate_subgrove_key(
                "private-1",
                2,
                vec![key_grant("did:willow:a"), key_grant("did:willow:b")],
                OWNER,
                &seed_key(),
                KEY_ID,
                22,
            )
            .await
            .unwrap();
        privacy
            .revoke_subgrove_key("private-1", "did:willow:b", OWNER, &seed_key(), KEY_ID, 23)
            .await
            .unwrap();

        let grant_lines = |g: &EncryptedKeyGrant| {
            format!(
                "Grantee: {}\nGranteeKey: {}\nKeyEpoch: {}\nEphemeralKey: {}\nEncryptedKey: {}\n\
                 GrantedBy: {}\nGrantedAt: {}",
                g.grantee_did,
                g.grantee_public_key_id,
                g.key_epoch,
                hex::encode(&g.ephemeral_public_key),
                hex::encode(&g.encrypted_key),
                g.granted_by,
                g.granted_at
            )
        };
        let sent = broadcast(&server).await;
        let [Transaction::GrantSubgroveKey(grant), Transaction::RotateSubgroveKey(rotate), Transaction::RevokeSubgroveKey(revoke)] =
            sent.as_slice()
        else {
            panic!("expected a grant, a rotation, and a revoke, got {sent:?}");
        };
        assert_eq!(grant.nonce, 21);
        assert_eq!(grant.encrypted_key_grant.encrypted_key, vec![0x51; 72]);
        assert_signed(
            &format!(
                "GrantSubgroveKey\nSubgrove: {}\nSender: {}\n{}\nNonce: {}",
                grant.subgrove_id,
                grant.sender_did,
                grant_lines(&grant.encrypted_key_grant),
                grant.nonce
            ),
            &grant.signature,
        );
        assert_eq!(rotate.nonce, 22);
        assert_signed(
            &format!(
                "RotateSubgroveKey\nSubgrove: {}\nSender: {}\nNewEpoch: {}\nGrants: {}\n{}\nNonce: {}",
                rotate.subgrove_id,
                rotate.sender_did,
                rotate.new_epoch,
                rotate.new_grants.len(),
                rotate
                    .new_grants
                    .iter()
                    .map(grant_lines)
                    .collect::<Vec<_>>()
                    .join("\n"),
                rotate.nonce
            ),
            &rotate.signature,
        );
        assert_eq!(revoke.nonce, 23);
        assert_signed(
            &format!(
                "RevokeSubgroveKey:{}:{}:{}:{}",
                revoke.subgrove_id, revoke.revokee_did, revoke.sender_did, revoke.nonce
            ),
            &revoke.signature,
        );
    }

    #[tokio::test]
    async fn a_refused_grant_or_revoke_sends_nothing() {
        let server = mock_chain(0).await;
        let client = file_client(&server).await;
        let privacy = client.privacy();
        let err = privacy
            .grant_subgrove_key(
                "private-1",
                key_grant("did:willow:b\nGrantee: did:willow:c"),
                OWNER,
                &seed_key(),
                KEY_ID,
                21,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, WillowError::Validation(_)), "{err}");
        let err = privacy
            .revoke_subgrove_key("a:b", "did:willow:b", OWNER, &seed_key(), KEY_ID, 22)
            .await
            .unwrap_err();
        assert!(matches!(err, WillowError::Validation(_)), "{err}");
        assert!(broadcast(&server).await.is_empty());
    }

    #[tokio::test]
    async fn unregister_storage_node_signs_its_node_and_nonce() {
        let server = mock_chain(13).await;
        let client = file_client(&server).await;
        client
            .files()
            .unregister_storage_node(OWNER, &seed_key(), KEY_ID)
            .await
            .unwrap();

        let sent = broadcast(&server).await;
        let [Transaction::UnregisterStorageNode(tx)] = sent.as_slice() else {
            panic!("expected one UnregisterStorageNode, got {sent:?}");
        };
        assert_eq!(tx.nonce, 14);
        assert_eq!(tx.public_key_id, KEY_ID);
        assert_signed(
            &format!(
                "UnregisterStorageNode\nNode: {}\nNonce: {}",
                tx.node_did, tx.nonce
            ),
            &tx.signature,
        );
    }

    /// Without a consensus URL a transaction has no server to go to: a clear error, not a panic.
    #[tokio::test]
    async fn a_write_without_a_consensus_url_is_a_clear_error() {
        let server = MockServer::start().await;
        let client = WillowClient::builder()
            .api_url(&server.uri())
            .build()
            .await
            .unwrap();
        client.set_identity_with_algorithm(OWNER, SEED_HEX, KEY_ID, SignatureAlgorithm::Ed25519);
        let err = client
            .privacy()
            .grant_subgrove_key(
                "private-1",
                key_grant("did:willow:b"),
                OWNER,
                &seed_key(),
                KEY_ID,
                1,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, WillowError::Config(m) if m.contains("consensus_url")),
            "{err}"
        );
        let err = client
            .files()
            .unregister_storage_node(OWNER, &seed_key(), KEY_ID)
            .await
            .unwrap_err();
        assert!(matches!(err, WillowError::Config(_)), "{err}");
        let err = client
            .files()
            .delete("files-1", "photo.png", Some(&seed_key()), Some(KEY_ID))
            .await
            .unwrap_err();
        assert!(matches!(err, WillowError::Config(_)), "{err}");
    }
}
