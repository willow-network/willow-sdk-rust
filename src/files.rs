//! File storage operations for Willow.
//!
//! Provides upload, download, metadata, listing, and deletion of files
//! stored in FileStorage subgroves. Files are chunked locally, manifests
//! go through consensus, and chunks are uploaded to storage nodes.

use crate::client::WillowClient;
use crate::errors::{Result, WillowError};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default chunk size for file splitting (256 KB).
pub const DEFAULT_CHUNK_SIZE: u32 = 262_144;

/// File manifest metadata returned from the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub file_key: String,
    pub filename: String,
    pub content_type: String,
    pub total_size: u64,
    pub content_hash: String,
    pub chunk_count: u32,
    pub chunk_size: u32,
    pub chunk_merkle_root: String,
    pub owner_did: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub encrypted: bool,
    #[serde(default)]
    pub storage_nodes: Vec<String>,
}

/// File list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileListResponse {
    pub files: Vec<FileManifest>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub limit: u16,
}

/// File storage operations.
pub struct FileOperations {
    client: WillowClient,
}

impl FileOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Upload a file to a FileStorage subgrove.
    ///
    /// The manifest transaction is signed with `signing_key` over
    /// [`crate::signed_messages::store_file_manifest`], which binds every manifest field and the
    /// nonce taken here, under `public_key_id`. The node refuses an unsigned manifest, so without
    /// both this is refused ([`WillowError::Validation`]) before anything is sent; they are
    /// `Option`s only for compatibility.
    ///
    /// Chunks go to the storage node only once the manifest has landed in a block and executed:
    /// storage nodes check the on-chain manifest before they accept chunks. A manifest not in a
    /// block within about 30 s, or refused in its block (which spends its nonce), is an error and
    /// no chunk is sent.
    pub async fn upload(
        &self,
        subgrove_id: &str,
        file_key: &str,
        filename: &str,
        data: &[u8],
        storage_node_endpoint: &str,
        signing_key: Option<&SigningKey>,
        public_key_id: Option<&str>,
    ) -> Result<FileManifest> {
        self.ensure_authenticated()?;
        let (signing_key, pub_key_id) = require_signing("upload", signing_key, public_key_id)?;

        let chunk_size = DEFAULT_CHUNK_SIZE;
        let chunks = chunk_data(data, chunk_size);
        let chunk_count = chunks.len() as u32;

        // Compute chunk hashes and content hash
        let content_hash: [u8; 32] = Sha256::digest(data).into();
        let chunk_hashes: Vec<[u8; 32]> = chunks.iter().map(|c| Sha256::digest(c).into()).collect();
        let chunk_merkle_root = compute_merkle_root(&chunk_hashes);

        let owner_did = self.client.get_did().ok_or_else(|| {
            WillowError::Authentication("Set identity before file operations".to_string())
        })?;
        let content_hash_hex = hex::encode(content_hash);
        let content_type = guess_content_type(filename);

        let consensus = self.client.require_consensus("upload")?;

        // Submit the manifest to consensus via the CometBFT RPC, as the chain's own
        // StoreFileManifestTx.
        use crate::signed_messages::{self, StoreFileManifestTx};
        use willow_types::consensus::transactions::Transaction;

        let tx_hash = consensus
            .submit_with_nonce(&owner_did, |nonce| {
                let mut manifest_tx = StoreFileManifestTx {
                    subgrove_id: subgrove_id.to_string(),
                    file_key: file_key.to_string(),
                    filename: filename.to_string(),
                    content_type: content_type.clone(),
                    total_size: data.len() as u64,
                    content_hash,
                    chunk_count,
                    chunk_size,
                    chunk_merkle_root,
                    owner_did: owner_did.clone(),
                    encryption: None,
                    signature: vec![],
                    public_key_id: pub_key_id,
                    nonce,
                };
                let message = signed_messages::store_file_manifest(&manifest_tx)?;
                manifest_tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
                Ok(Transaction::StoreFileManifest(manifest_tx))
            })
            .await?;

        // Storage nodes verify the on-chain manifest before accepting chunks.
        match consensus.wait_for_tx_outcome(&tx_hash, 15).await? {
            None => {
                return Err(WillowError::Custom(format!(
                    "the manifest transaction {tx_hash} is not in a block yet; no chunk was \
                     uploaded (wait for it to land, then upload the chunks)"
                )))
            }
            Some(outcome) if outcome.code != 0 => {
                return Err(WillowError::Custom(format!(
                    "the manifest transaction {tx_hash} was refused in block {}: {} (code: {})",
                    outcome.height, outcome.log, outcome.code
                )))
            }
            Some(_) => {}
        }

        // Upload chunks to storage node
        let http = crate::client::http_client_with_timeout(self.client.timeout);
        for (i, chunk) in chunks.iter().enumerate() {
            let url = format!(
                "{}/upload/{}/{}?chunk_index={}&chunk_count={}&content_hash={}",
                storage_node_endpoint, subgrove_id, file_key, i, chunk_count, content_hash_hex
            );
            let resp = http
                .post(&url)
                .body(chunk.to_vec())
                .send()
                .await
                .map_err(|e| WillowError::Network(format!("Chunk upload failed: {}", e)))?;

            if !resp.status().is_success() {
                let body = crate::http_body::text(resp, crate::http_body::SMALL)
                    .await
                    .unwrap_or_default();
                return Err(WillowError::Network(format!(
                    "Chunk {} upload failed: {}",
                    i, body
                )));
            }
        }

        Ok(FileManifest {
            file_key: file_key.to_string(),
            filename: filename.to_string(),
            content_type,
            total_size: data.len() as u64,
            content_hash: content_hash_hex,
            chunk_count,
            chunk_size,
            chunk_merkle_root: hex::encode(chunk_merkle_root),
            owner_did,
            created_at: 0,
            updated_at: 0,
            encrypted: false,
            storage_nodes: vec![storage_node_endpoint.to_string()],
        })
    }

    /// Download a file from a FileStorage subgrove.
    ///
    /// 1. Gets the manifest from the API ([`Self::metadata`]): the API's word, unproven. A
    ///    manifest the chain refuses (no data, over 1 GiB or 262,144 chunks, a chunk count that
    ///    doesn't fit the total and chunk sizes, or chunks under 4 KiB in a file of more than
    ///    one) is refused before any chunk is fetched.
    /// 2. Downloads chunks from a storage node, each refused once it passes the manifest's
    ///    chunk size (or the 2 MiB a storage node stores, [`crate::http_body::CHUNK`]), and
    ///    all of them once they pass its total size
    /// 3. Verifies the chunks against the manifest's chunk Merkle root, and the file's length
    ///    and hash against its total size and content hash
    pub async fn download(
        &self,
        subgrove_id: &str,
        file_key: &str,
        storage_node_endpoint: &str,
    ) -> Result<Vec<u8>> {
        let manifest = self.metadata(subgrove_id, file_key).await?;
        check_manifest(&manifest)?;

        let content_hash_hex = &manifest.content_hash;
        let chunk_count = manifest.chunk_count;
        let chunk_limit = (manifest.chunk_size as usize).min(crate::http_body::CHUNK);

        // Download chunks from storage node
        let http = crate::client::http_client_with_timeout(self.client.timeout);
        let mut file_data = Vec::new();
        let mut chunk_hashes = Vec::new();

        for i in 0..chunk_count {
            let url = format!(
                "{}/chunk/{}/{}/{}?content_hash={}",
                storage_node_endpoint, subgrove_id, file_key, i, content_hash_hex
            );
            let resp = http
                .get(&url)
                .send()
                .await
                .map_err(|e| WillowError::Network(format!("Chunk download failed: {}", e)))?;

            if !resp.status().is_success() {
                return Err(WillowError::Network(format!(
                    "Chunk {} download failed: HTTP {}",
                    i,
                    resp.status()
                )));
            }

            let chunk_data = match crate::http_body::read(resp, chunk_limit).await {
                Ok(chunk) => chunk,
                Err(WillowError::ResponseTooLarge { .. })
                    if chunk_limit == manifest.chunk_size as usize =>
                {
                    return Err(WillowError::ProofVerificationFailed(format!(
                        "chunk {i} is longer than the manifest's chunk size of {} bytes",
                        manifest.chunk_size
                    )))
                }
                Err(e @ WillowError::ResponseTooLarge { .. }) => return Err(e),
                Err(e) => {
                    return Err(WillowError::Network(format!(
                        "Failed to read chunk {}: {}",
                        i, e
                    )))
                }
            };
            if (file_data.len() + chunk_data.len()) as u64 > manifest.total_size {
                return Err(WillowError::ProofVerificationFailed(format!(
                    "the chunks run past the manifest's total size of {} bytes at chunk {i}",
                    manifest.total_size
                )));
            }

            let chunk_hash: [u8; 32] = Sha256::digest(&chunk_data).into();
            chunk_hashes.push(chunk_hash);
            file_data.extend_from_slice(&chunk_data);
        }

        // Verify chunk Merkle root
        let computed_root = compute_merkle_root(&chunk_hashes);
        let expected_root = hex::decode(&manifest.chunk_merkle_root).map_err(|e| {
            WillowError::ProofVerificationFailed(format!("Invalid merkle root hex: {}", e))
        })?;

        if computed_root != expected_root.as_slice() {
            return Err(WillowError::ProofVerificationFailed(
                "Chunk Merkle root mismatch".to_string(),
            ));
        }
        if file_data.len() as u64 != manifest.total_size {
            return Err(WillowError::ProofVerificationFailed(format!(
                "the chunks hold {} bytes, not the manifest's total size of {}",
                file_data.len(),
                manifest.total_size
            )));
        }

        // Verify content hash
        let computed_hash = Sha256::digest(&file_data);
        let expected_hash = hex::decode(content_hash_hex).map_err(|e| {
            WillowError::ProofVerificationFailed(format!("Invalid content hash hex: {}", e))
        })?;

        if computed_hash.as_slice() != expected_hash.as_slice() {
            return Err(WillowError::ProofVerificationFailed(
                "Content hash mismatch".to_string(),
            ));
        }

        Ok(file_data)
    }

    /// A file's manifest, as the API serves it (`GET /files/{subgrove}/{key}`): the API's word,
    /// with no proof checked.
    pub async fn metadata(&self, subgrove_id: &str, file_key: &str) -> Result<FileManifest> {
        self.client
            .request(
                "GET",
                &format!("/files/{}/{}", subgrove_id, file_key),
                None::<&()>,
                false,
            )
            .await
    }

    /// List all files in a subgrove.
    pub async fn list(&self, subgrove_id: &str) -> Result<Vec<FileManifest>> {
        let response: FileListResponse = self
            .client
            .request(
                "GET",
                &format!("/files/{}", subgrove_id),
                None::<&()>,
                false,
            )
            .await?;

        Ok(response.files)
    }

    /// Delete a file (submits DeleteFileManifestTx to consensus).
    ///
    /// The delete transaction is signed with `signing_key` over
    /// [`crate::signed_messages::delete_file_manifest`] with the nonce taken here, under
    /// `public_key_id`. Without both it is refused ([`WillowError::Validation`]) before anything
    /// is sent, as the node refuses an unsigned delete.
    pub async fn delete(
        &self,
        subgrove_id: &str,
        file_key: &str,
        signing_key: Option<&SigningKey>,
        public_key_id: Option<&str>,
    ) -> Result<()> {
        self.ensure_authenticated()?;
        let (signing_key, pub_key_id) = require_signing("delete", signing_key, public_key_id)?;

        let owner_did = self.client.get_did().ok_or_else(|| {
            WillowError::Authentication("Set identity before file operations".to_string())
        })?;

        let consensus = self.client.require_consensus("delete")?;

        use crate::signed_messages::{self, DeleteFileManifestTx};
        use willow_types::consensus::transactions::Transaction;

        consensus
            .submit_with_nonce(&owner_did, |nonce| {
                let mut delete_tx = DeleteFileManifestTx {
                    subgrove_id: subgrove_id.to_string(),
                    file_key: file_key.to_string(),
                    owner_did: owner_did.clone(),
                    signature: vec![],
                    public_key_id: pub_key_id,
                    nonce,
                };
                let message = signed_messages::delete_file_manifest(&delete_tx)?;
                delete_tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
                Ok(Transaction::DeleteFileManifest(delete_tx))
            })
            .await?;

        Ok(())
    }

    /// Unregister a storage node (submits UnregisterStorageNode to consensus).
    ///
    /// The `signing_key` signs [`crate::signed_messages::unregister_storage_node`] (`Node` and
    /// the nonce taken here).
    pub async fn unregister_storage_node(
        &self,
        node_did: &str,
        signing_key: &SigningKey,
        public_key_id: &str,
    ) -> Result<()> {
        use crate::signed_messages::{self, UnregisterStorageNodeTx};
        use willow_types::consensus::transactions::Transaction;

        let consensus = self.client.require_consensus("unregister_storage_node")?;
        consensus
            .submit_with_nonce(node_did, |nonce| {
                let mut tx = UnregisterStorageNodeTx {
                    node_did: node_did.to_string(),
                    signature: vec![],
                    public_key_id: public_key_id.to_string(),
                    nonce,
                };
                let message = signed_messages::unregister_storage_node(&tx)?;
                tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();
                Ok(Transaction::UnregisterStorageNode(tx))
            })
            .await?;

        Ok(())
    }

    fn ensure_authenticated(&self) -> Result<()> {
        if self.client.get_did().is_none() {
            return Err(WillowError::Authentication(
                "Set identity before file operations".to_string(),
            ));
        }
        Ok(())
    }
}

/// Refuse a manifest the chain refuses ([`willow_types::storage`]'s limits, as the node checks a
/// `StoreFileManifest`): no data (a zero total size, chunk count, or chunk size), more than
/// `MAX_FILE_SIZE` (1 GiB) or `MAX_CHUNK_COUNT` (262,144 chunks), a total size that the chunk
/// count and chunk size don't fit (`(count - 1) * size < total <= count * size`). Such a
/// manifest names no file the chain holds, and its counts would set what a download reads. (The
/// chain's minimum chunk size applies only to manifests from its activation height, so an older
/// one below it can exist.)
fn check_manifest(manifest: &FileManifest) -> Result<()> {
    use willow_types::storage::{MAX_CHUNK_COUNT, MAX_FILE_SIZE};
    let (total, count, size) = (
        manifest.total_size,
        manifest.chunk_count as u64,
        manifest.chunk_size as u64,
    );
    let why = if total == 0 || count == 0 || size == 0 {
        "it holds no data".to_string()
    } else if total > MAX_FILE_SIZE {
        format!("{total} bytes, over the chain's maximum of {MAX_FILE_SIZE}")
    } else if count > MAX_CHUNK_COUNT as u64 {
        format!("{count} chunks, over the chain's maximum of {MAX_CHUNK_COUNT}")
    } else if total > count * size || total <= (count - 1) * size {
        format!("{count} chunks of {size} bytes don't hold {total} bytes")
    } else {
        return Ok(());
    };
    Err(WillowError::ProofVerificationFailed(format!(
        "the manifest of {} is one the chain refuses: {why}",
        manifest.file_key
    )))
}

/// The key and key ID a file transaction is signed with: the node refuses one unsigned.
fn require_signing<'a>(
    operation: &str,
    signing_key: Option<&'a SigningKey>,
    public_key_id: Option<&str>,
) -> Result<(&'a SigningKey, String)> {
    match (signing_key, public_key_id) {
        (Some(key), Some(id)) if !id.is_empty() => Ok((key, id.to_string())),
        _ => Err(WillowError::Validation(format!(
            "{operation} needs a signing key and its public key ID: the node refuses an unsigned \
             file transaction"
        ))),
    }
}

/// Split data into chunks of the given size.
fn chunk_data(data: &[u8], chunk_size: u32) -> Vec<&[u8]> {
    data.chunks(chunk_size as usize).collect()
}

/// Compute a Merkle root from chunk hashes.
fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    // No early return for single-leaf: pad to [leaf, leaf] and hash.
    // This prevents availability proof forgery for single-chunk files.

    let mut current = hashes.to_vec();
    if current.len() == 1 {
        current.push(current[0]);
    }
    while current.len() > 1 {
        if current.len() % 2 != 0 {
            let last = *current.last().unwrap();
            current.push(last);
        }
        let mut next = Vec::new();
        for pair in current.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            hasher.update(pair[1]);
            next.push(hasher.finalize().into());
        }
        current = next;
    }
    current[0]
}

/// Encryption metadata for private file subgroves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEncryption {
    pub key_epoch: u64,
    pub nonce: [u8; 24],
}

/// Encrypt file data using XChaCha20-Poly1305.
///
/// Returns (ciphertext, nonce). The `key` should be the 32-byte symmetric key
/// obtained from the private subgrove key grant system.
pub fn encrypt_file(data: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 24])> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use rand::RngCore;

    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| WillowError::Crypto(format!("Encryption failed: {}", e)))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt file data using XChaCha20-Poly1305.
///
/// The `key` should be the 32-byte symmetric key obtained from the private
/// subgrove key grant system.
pub fn decrypt_file(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };

    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| WillowError::Crypto(format!("Decryption failed: {}", e)))
}

/// Guess MIME type from filename extension.
fn guess_content_type(filename: &str) -> String {
    match filename.rsplit('.').next() {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("pdf") => "application/pdf",
        Some("json") => "application/json",
        Some("txt") => "text/plain",
        Some("html") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("wasm") => "application/wasm",
        Some("zip") => "application/zip",
        Some("mp4") => "video/mp4",
        Some("mp3") => "audio/mpeg",
        _ => "application/octet-stream",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SignatureAlgorithm;
    use wiremock::MockServer;

    #[tokio::test]
    async fn unsigned_uploads_and_deletes_are_refused_before_anything_is_sent() {
        let server = MockServer::start().await;
        let client = WillowClient::builder()
            .api_url(&server.uri())
            .consensus_url(&server.uri())
            .build()
            .await
            .unwrap();
        client.set_identity_with_algorithm(
            "did:willow:a",
            &"03".repeat(32),
            "did:willow:a#key-1",
            SignatureAlgorithm::Ed25519,
        );
        let files = client.files();
        let err = files
            .upload("sg", "k", "a.txt", b"hello", &server.uri(), None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, WillowError::Validation(_)), "{err}");
        let err = files.delete("sg", "k", None, None).await.unwrap_err();
        assert!(matches!(err, WillowError::Validation(_)), "{err}");
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A manifest of `chunks`' hashes, with the sizes given (which needn't fit them).
    fn manifest(chunks: &[Vec<u8>], count: u32, chunk_size: u32, total: u64) -> serde_json::Value {
        let hashes: Vec<[u8; 32]> = chunks.iter().map(|c| Sha256::digest(c).into()).collect();
        serde_json::json!({
            "file_key": "k", "filename": "f.bin", "content_type": "application/octet-stream",
            "total_size": total,
            "content_hash": hex::encode(Sha256::digest(chunks.concat())),
            "chunk_count": count, "chunk_size": chunk_size,
            "chunk_merkle_root": hex::encode(compute_merkle_root(&hashes)),
            "owner_did": "did:willow:a", "created_at": 0, "updated_at": 0, "encrypted": false,
        })
    }

    /// Download `k` from a server that is both the API, serving `manifest`, and the storage
    /// node, serving `chunks`; with the chunk requests the storage node received.
    async fn download(manifest: serde_json::Value, chunks: &[Vec<u8>]) -> (Result<Vec<u8>>, usize) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/sg/k"))
            .respond_with(ResponseTemplate::new(200).set_body_json(manifest))
            .mount(&server)
            .await;
        for (i, chunk) in chunks.iter().enumerate() {
            Mock::given(method("GET"))
                .and(path(format!("/chunk/sg/k/{i}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(chunk.clone()))
                .mount(&server)
                .await;
        }
        let client = WillowClient::builder()
            .api_url(&server.uri())
            .build()
            .await
            .unwrap();
        let result = client.files().download("sg", "k", &server.uri()).await;
        let sent = server.received_requests().await.unwrap();
        let chunk_requests = sent
            .iter()
            .filter(|r| r.url.path().starts_with("/chunk/"))
            .count();
        (result, chunk_requests)
    }

    #[tokio::test]
    async fn a_download_reads_chunks_that_fit_the_manifest() {
        let chunks = vec![vec![1u8; 4096], vec![2u8; 10]];
        let (result, _) = download(manifest(&chunks, 2, 4096, 4106), &chunks).await;
        assert_eq!(result.unwrap(), chunks.concat());
    }

    /// The manifest is the API's, unproven: one the chain would refuse (no data, over 1 GiB or
    /// 262,144 chunks, a chunk count that doesn't fit the total and chunk sizes, or chunks
    /// under 4 KiB in a file of more than one) is refused before any chunk is fetched.
    #[tokio::test]
    async fn a_manifest_the_chain_would_refuse_is_refused_before_any_chunk_is_fetched() {
        let chunks = vec![vec![7u8; 10], vec![8u8; 10]];
        for (count, chunk_size, total) in [
            (0, 4096, 0),
            (1, 0, 0),
            (1025, 1 << 20, (1 << 30) + 1),
            (262_145, 4096, 262_144 * 4096 + 1),
            (u32::MAX, 1, u32::MAX as u64),
            (3, 4096, 10),
            (2, 8, 17),
        ] {
            let (result, fetched) =
                download(manifest(&chunks, count, chunk_size, total), &chunks).await;
            assert!(result.is_err(), "{count} x {chunk_size} for {total}");
            assert_eq!(fetched, 0, "{count} x {chunk_size} for {total}");
        }
    }

    /// A storage node and API that agree can still serve more than the manifest says: a chunk
    /// longer than `chunk_size`, or chunks that run past `total_size`, are refused.
    #[tokio::test]
    async fn chunks_longer_than_the_manifest_says_are_refused() {
        let long = vec![vec![3u8; 8192]];
        let (result, _) = download(manifest(&long, 1, 4096, 4096), &long).await;
        assert!(
            result.is_err(),
            "a chunk over chunk_size: {:?}",
            result.map(|d| d.len())
        );

        let past = vec![vec![4u8; 4096], vec![5u8; 4096]];
        let (result, _) = download(manifest(&past, 2, 4096, 4097), &past).await;
        assert!(
            result.is_err(),
            "past total_size: {:?}",
            result.map(|d| d.len())
        );
    }
}
