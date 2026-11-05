//! Caps on the size of the answers the SDK reads, one per kind of answer.
//!
//! The SDK reads an answer's body a piece at a time and stops once it passes the cap of its
//! route, refusing it with [`WillowError::ResponseTooLarge`] before decoding any of it (an
//! answer that declares a longer length is refused before any is read), so a server can't make
//! it hold an answer of any size. Such an answer is not retried.
//!
//! A cap bounds the bytes read, not the memory decoding them takes, which can be a multiple of
//! it: a JSON list of empty objects or arrays decodes to tens of bytes per element.
//!
//! Each cap is the smallest that holds the largest honest answer of its routes where the node
//! bounds that answer. Where the request sets an answer's size (a query's limit) and the node
//! sets no maximum, the cap is [`LARGE`], and an answer past it is refused: ask for less.

use crate::errors::{Result, WillowError};
use serde::de::DeserializeOwned;

/// Answers of a fixed shape, or lists the node keeps short: health, root hashes, a value read
/// by key (`/data`, at most what one transaction writes), an account's nonce, balances, the
/// token's information, the fee schedule, DID documents and permissions, key grants, subgrove,
/// validator, and indexer information and lists, checkpoint roots, a file's manifest and a page
/// of the file list (at most 100 files), ERC-8004 answers (at most 100 entries), and CometBFT's
/// `status`, `commit`, `validators` (at most 100 a page), `abci_query`, and `broadcast_tx_sync`.
/// These are a few KiB; 4 MiB is the chain's `max_tx_bytes`, the most one transaction writes.
/// The subgrove, validator, and indexer lists aren't paged, so they grow with the chain: an
/// entry is about 1 KiB unless its schema is long, so 4 MiB holds thousands.
pub const SMALL: usize = 4 << 20;

/// The API's `/proof` answers: a proof of one key in hex, twice its length, of at most
/// `grovedb_envelope::MAX_PROOF_BYTES` (1 MiB), with the JSON around it.
pub const PROOF: usize = (2 << 20) + (64 << 10);

/// A file chunk: the storage node's upload route takes a body of at most 2 MiB (axum's default
/// body limit), so it stores no longer chunk. A download reads each chunk under the manifest's
/// chunk size when that is smaller.
pub const CHUNK: usize = 2 << 20;

/// CometBFT's `tx`: a transaction of at most `max_tx_bytes` (4 MiB) is 5.4 MiB in base64, with
/// its result beside it.
pub const TX: usize = 12 << 20;

/// A verifiable-RPC answer: the GKR and completeness proofs of one indexer submission (a
/// transaction, so at most `max_tx_bytes`, 4 MiB, in all), the GKR proofs as JSON arrays of
/// numbers (up to 4 bytes for each byte), beside the GroveDB proof (at most 1 MiB) and the
/// answer in base64.
pub const VERIFIABLE_RPC: usize = 20 << 20;

/// Answers whose size the request sets, with no maximum on the node: a `/query` page (100
/// documents unless the query sets a limit, each at most `max_data_payload_bytes`, 512 KiB:
/// 50 MiB), a historical query, GraphQL and SQL answers, a block's matched logs, Ethereum state
/// and call answers (proofs of as many slots as asked for, or as the call touched), and
/// CometBFT's `block_results` (a result for each of a block's transactions).
pub const LARGE: usize = 64 << 20;

/// `resp`'s body, refused with [`WillowError::ResponseTooLarge`] once it passes `limit` bytes.
pub(crate) async fn read(mut resp: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if resp.content_length().is_some_and(|len| len > limit as u64) {
        return Err(WillowError::ResponseTooLarge { limit });
    }
    let mut body = Vec::new();
    while let Some(piece) = resp.chunk().await? {
        if piece.len() > limit - body.len() {
            return Err(WillowError::ResponseTooLarge { limit });
        }
        body.extend_from_slice(&piece);
    }
    Ok(body)
}

/// `resp`'s body as text (invalid UTF-8 replaced), under `limit` as [`read`] reads it.
pub(crate) async fn text(resp: reqwest::Response, limit: usize) -> Result<String> {
    let body = read(resp, limit).await?;
    Ok(String::from_utf8(body)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// `resp`'s body decoded from JSON, under `limit` as [`read`] reads it.
pub(crate) async fn json<T: DeserializeOwned>(resp: reqwest::Response, limit: usize) -> Result<T> {
    serde_json::from_slice(&read(resp, limit).await?).map_err(WillowError::Serialization)
}
