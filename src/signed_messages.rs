//! The messages data and file writes are signed over.
//!
//! Each is a set of lines joined by `\n` with no trailing newline: the kind, then one
//! `Label: value` line per field the transaction writes, the nonce last. Variable-length bytes
//! appear as the lowercase hex SHA-256 of the exact bytes the transaction carries. Each builder
//! reads the transaction it signs, so build the message after the nonce is chosen.
//!
//! A text field holding a line break is refused, as the node refuses it.

use crate::errors::{Result, WillowError};
use sha2::{Digest, Sha256};

pub use willow_types::consensus::transactions::{
    DeleteDataTx, DeleteFileManifestTx, StoreDataTx, StoreFileManifestTx, UpdateDataTx,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::sign_challenge;
    use crate::client::WillowClient;
    use crate::consensus::ConsensusClient;
    use crate::types::{SignatureAlgorithm, StoreDataRequest};
    use base64::Engine;
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use serde_json::json;
    use sha3::Keccak256;
    use willow_types::consensus::transactions::Transaction;
    use willow_types::storage::FileEncryption;
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
        assert_eq!(vectors.len(), 6);
        for v in vectors {
            let name = v["name"].as_str().unwrap();
            let i = &v["inputs"];
            let s = |k: &str| i[k].as_str().unwrap().to_string();
            let n = |k: &str| i[k].as_u64().unwrap();
            let message = match name {
                "StoreData" => store_data(&StoreDataTx {
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

    /// Every transaction broadcast to `server`, decoded from the bincode the node reads.
    async fn broadcast(server: &MockServer) -> Vec<Transaction> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter_map(|r| r.body_json::<serde_json::Value>().ok())
            .filter(|b| b["method"] == "broadcast_tx_sync")
            .map(|b| {
                let tx = base64::engine::general_purpose::STANDARD
                    .decode(b["params"]["tx"].as_str().unwrap())
                    .unwrap();
                bincode::deserialize(&tx).unwrap()
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
}
