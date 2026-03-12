//! File storage operations for Willow.
//!
//! Provides upload, download, metadata, listing, and deletion of files
//! stored in FileStorage subgroves. Files are chunked locally, manifests
//! go through consensus, and chunks are uploaded to storage nodes.

use crate::client::WillowClient;
use crate::errors::{Result, WillowError};
use crate::types::ApiResponse;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    /// When `signing_key` is provided, the manifest transaction is signed with
    /// the given Ed25519 key. The `public_key_id` and `nonce` are required for
    /// signed transactions.
    pub async fn upload(
        &self,
        app_id: &str,
        subgrove_id: &str,
        file_key: &str,
        filename: &str,
        data: &[u8],
        storage_node_endpoint: &str,
        signing_key: Option<&SigningKey>,
        public_key_id: Option<&str>,
        nonce: Option<u64>,
    ) -> Result<FileManifest> {
        self.ensure_authenticated()?;

        let chunk_size = DEFAULT_CHUNK_SIZE;
        let chunks = chunk_data(data, chunk_size);
        let chunk_count = chunks.len() as u32;

        // Compute chunk hashes and content hash
        let content_hash: [u8; 32] = Sha256::digest(data).into();
        let chunk_hashes: Vec<[u8; 32]> = chunks
            .iter()
            .map(|c| Sha256::digest(c).into())
            .collect();
        let chunk_merkle_root = compute_merkle_root(&chunk_hashes);

        let owner_did = self.client.get_did()
            .ok_or_else(|| WillowError::Authentication("Set identity before file operations".to_string()))?;
        let content_hash_hex = hex::encode(content_hash);
        let content_type = guess_content_type(filename);

        // Sign the transaction if a signing key is provided
        let (signature_bytes, pub_key_id, tx_nonce) = if let Some(key) = signing_key {
            let message = format!(
                "store_file:{}:{}:{}:{}:{}",
                app_id, subgrove_id, file_key, content_hash_hex, data.len()
            );
            let signature = key.sign(message.as_bytes());
            (
                signature.to_bytes().to_vec(),
                public_key_id.unwrap_or("").to_string(),
                nonce.unwrap_or(0),
            )
        } else {
            (vec![], String::new(), 0)
        };

        // Submit manifest to consensus via the consensus RPC
        let manifest_tx = serde_json::json!({
            "StoreFileManifest": {
                "app_id": app_id,
                "subgrove_id": subgrove_id,
                "file_key": file_key,
                "filename": filename,
                "content_type": content_type,
                "total_size": data.len() as u64,
                "content_hash": content_hash_hex,
                "chunk_count": chunk_count,
                "chunk_size": chunk_size,
                "chunk_merkle_root": hex::encode(chunk_merkle_root),
                "owner_did": &owner_did,
                "signature": signature_bytes,
                "public_key_id": pub_key_id,
                "nonce": tx_nonce
            }
        });

        // Broadcast manifest via consensus
        self.client
            .request::<Value, _>("POST", "/broadcast_tx", Some(&manifest_tx), true)
            .await?;

        // Upload chunks to storage node
        let http = reqwest::Client::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let url = format!(
                "{}/upload/{}/{}/{}?chunk_index={}&chunk_count={}&content_hash={}",
                storage_node_endpoint, app_id, subgrove_id, file_key, i, chunk_count, content_hash_hex
            );
            let resp = http.post(&url).body(chunk.to_vec()).send().await
                .map_err(|e| WillowError::Network(format!("Chunk upload failed: {}", e)))?;

            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(WillowError::Network(
                    format!("Chunk {} upload failed: {}", i, body),
                ));
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
    /// 1. Gets the manifest from the validator API (with GroveDB proof)
    /// 2. Downloads chunks from a storage node
    /// 3. Verifies each chunk against the chunk Merkle tree
    /// 4. Verifies the reassembled file against the content hash
    pub async fn download(
        &self,
        app_id: &str,
        subgrove_id: &str,
        file_key: &str,
        storage_node_endpoint: &str,
    ) -> Result<Vec<u8>> {
        // Get manifest from validator
        let manifest = self.metadata(app_id, subgrove_id, file_key).await?;

        let content_hash_hex = &manifest.content_hash;
        let chunk_count = manifest.chunk_count;

        // Download chunks from storage node
        let http = reqwest::Client::new();
        let mut file_data = Vec::new();
        let mut chunk_hashes = Vec::new();

        for i in 0..chunk_count {
            let url = format!(
                "{}/chunk/{}/{}/{}/{}?content_hash={}",
                storage_node_endpoint, app_id, subgrove_id, file_key, i, content_hash_hex
            );
            let resp = http.get(&url).send().await
                .map_err(|e| WillowError::Network(format!("Chunk download failed: {}", e)))?;

            if !resp.status().is_success() {
                return Err(WillowError::Network(
                    format!("Chunk {} download failed: HTTP {}", i, resp.status()),
                ));
            }

            let chunk_data = resp.bytes().await
                .map_err(|e| WillowError::Network(format!("Failed to read chunk {}: {}", i, e)))?;

            let chunk_hash: [u8; 32] = Sha256::digest(&chunk_data).into();
            chunk_hashes.push(chunk_hash);
            file_data.extend_from_slice(&chunk_data);
        }

        // Verify chunk Merkle root
        let computed_root = compute_merkle_root(&chunk_hashes);
        let expected_root = hex::decode(&manifest.chunk_merkle_root)
            .map_err(|e| WillowError::ProofVerificationFailed(format!("Invalid merkle root hex: {}", e)))?;

        if computed_root != expected_root.as_slice() {
            return Err(WillowError::ProofVerificationFailed(
                "Chunk Merkle root mismatch".to_string(),
            ));
        }

        // Verify content hash
        let computed_hash = Sha256::digest(&file_data);
        let expected_hash = hex::decode(content_hash_hex)
            .map_err(|e| WillowError::ProofVerificationFailed(format!("Invalid content hash hex: {}", e)))?;

        if computed_hash.as_slice() != expected_hash.as_slice() {
            return Err(WillowError::ProofVerificationFailed(
                "Content hash mismatch".to_string(),
            ));
        }

        Ok(file_data)
    }

    /// Get file manifest metadata with GroveDB proof.
    pub async fn metadata(
        &self,
        app_id: &str,
        subgrove_id: &str,
        file_key: &str,
    ) -> Result<FileManifest> {
        let response: ApiResponse<FileManifest> = self
            .client
            .request(
                "GET",
                &format!("/files/{}/{}/{}", app_id, subgrove_id, file_key),
                None::<&()>,
                false,
            )
            .await?;

        response
            .data
            .ok_or_else(|| WillowError::NotFound(format!("File not found: {}", file_key)))
    }

    /// List all files in a subgrove.
    pub async fn list(
        &self,
        app_id: &str,
        subgrove_id: &str,
    ) -> Result<Vec<FileManifest>> {
        let response: ApiResponse<FileListResponse> = self
            .client
            .request(
                "GET",
                &format!("/files/{}/{}", app_id, subgrove_id),
                None::<&()>,
                false,
            )
            .await?;

        Ok(response.data.map(|r| r.files).unwrap_or_default())
    }

    /// Delete a file (submits DeleteFileManifestTx to consensus).
    ///
    /// When `signing_key` is provided, the delete transaction is signed.
    pub async fn delete(
        &self,
        app_id: &str,
        subgrove_id: &str,
        file_key: &str,
        signing_key: Option<&SigningKey>,
        public_key_id: Option<&str>,
        nonce: Option<u64>,
    ) -> Result<()> {
        self.ensure_authenticated()?;

        let owner_did = self.client.get_did()
            .ok_or_else(|| WillowError::Authentication("Set identity before file operations".to_string()))?;

        let (signature_bytes, pub_key_id, tx_nonce) = if let Some(key) = signing_key {
            let message = format!(
                "delete_file:{}:{}:{}",
                app_id, subgrove_id, file_key
            );
            let signature = key.sign(message.as_bytes());
            (
                signature.to_bytes().to_vec(),
                public_key_id.unwrap_or("").to_string(),
                nonce.unwrap_or(0),
            )
        } else {
            (vec![], String::new(), 0)
        };

        let delete_tx = serde_json::json!({
            "DeleteFileManifest": {
                "app_id": app_id,
                "subgrove_id": subgrove_id,
                "file_key": file_key,
                "owner_did": &owner_did,
                "signature": signature_bytes,
                "public_key_id": pub_key_id,
                "nonce": tx_nonce
            }
        });

        self.client
            .request::<Value, _>("POST", "/broadcast_tx", Some(&delete_tx), true)
            .await?;

        Ok(())
    }

    /// Unregister a storage node (submits UnregisterStorageNode to consensus).
    ///
    /// The `signing_key` signs the message `"unregister_storage_node:{node_did}"`.
    pub async fn unregister_storage_node(
        &self,
        node_did: &str,
        signing_key: &SigningKey,
        public_key_id: &str,
        nonce: u64,
    ) -> Result<()> {
        let message = format!("unregister_storage_node:{}", node_did);
        let signature = signing_key.sign(message.as_bytes());

        let tx = serde_json::json!({
            "UnregisterStorageNode": {
                "node_did": node_did,
                "signature": signature.to_bytes().to_vec(),
                "public_key_id": public_key_id,
                "nonce": nonce
            }
        });

        self.client
            .request::<Value, _>("POST", "/broadcast_tx", Some(&tx), true)
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
