//! Client-side cryptographic completeness verification.
//!
//! When a subgrove runs with cryptographic completeness enabled, the chain
//! stores a 32-byte `events_commitment` for each indexed block: a domain-
//! separated keccak-256 hash over *exactly* the filter-matched event set the
//! block's receipts trie attests to. That commitment is the trusted anchor.
//!
//! An indexer can serve the matched-log preimage for a `(subgrove, block)`.
//! A client re-hashes that preimage with [`canonical_event_set_hash`] and
//! compares it to the on-chain commitment via [`verify_served_events`]. If they
//! match, the served set is provably the complete, untampered filter-matched
//! set the chain attests to — without trusting the indexer.
//!
//! This mirrors willow's on-chain `canonical_event_set_hash`
//! (`willow-network::data_sources::types`, consensus
//! `indexed_data_handler::full_block_auth`). The byte layout here is
//! byte-identical to that native implementation; the test vectors below are the
//! cross-language correctness gate.

use crate::client::WillowClient;
use crate::errors::{Result, WillowError};
use serde::Deserialize;
use sha3::{Digest, Keccak256};

/// Domain-separation tag for the completeness event-set commitment (v1).
///
/// 23 ASCII bytes, no null terminator.
const DOMAIN_TAG: &[u8] = b"WILLOW_CRYPTO_EVENTS_V1";

/// A single filter-matched Ethereum log, reduced to the consensus-derivable,
/// receipts-root-bound fields that the completeness commitment binds.
///
/// Deliberately excludes `transaction_hash`, log/transaction indices, and
/// block-header fields — only `(address, topics, data)` are committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    /// 20-byte contract address that emitted the log.
    pub address: [u8; 20],
    /// Indexed topics, each a 32-byte value (`topics[0]` is the event signature).
    pub topics: Vec<[u8; 32]>,
    /// Non-indexed log data, raw bytes.
    pub data: Vec<u8>,
}

impl Log {
    /// Construct a [`Log`] from its committed fields.
    pub fn new(address: [u8; 20], topics: Vec<[u8; 32]>, data: Vec<u8>) -> Self {
        Self {
            address,
            topics,
            data,
        }
    }
}

/// Compute the canonical 32-byte completeness commitment over a block's
/// filter-matched event set, in order.
///
/// The preimage is keccak-256 (Ethereum keccak, **not** NIST SHA3-256) over,
/// with all integers big-endian and no separators:
///
/// - the ASCII bytes `"WILLOW_CRYPTO_EVENTS_V1"` (23 bytes)
/// - `block_number` as `u64` big-endian (8 bytes)
/// - `matched_logs.len()` as `u64` big-endian (8 bytes)
/// - then, for each log in order:
///   - `address` (20 bytes)
///   - `topics.len()` as `u32` big-endian (4 bytes)
///   - each topic (32 bytes)
///   - `data.len()` as `u32` big-endian (4 bytes)
///   - `data` (raw bytes)
///
/// Byte-identical to willow's native `canonical_event_set_hash`.
pub fn canonical_event_set_hash(block_number: u64, matched_logs: &[Log]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(DOMAIN_TAG);
    hasher.update(block_number.to_be_bytes());
    hasher.update((matched_logs.len() as u64).to_be_bytes());
    for log in matched_logs {
        hasher.update(log.address);
        hasher.update((log.topics.len() as u32).to_be_bytes());
        for topic in &log.topics {
            hasher.update(topic);
        }
        hasher.update((log.data.len() as u32).to_be_bytes());
        hasher.update(&log.data);
    }
    hasher.finalize().into()
}

/// Verify that an indexer's served matched-log set for a block matches the
/// on-chain `events_commitment`.
///
/// Returns `true` iff [`canonical_event_set_hash`] of `(block_number,
/// matched_logs)` equals `commitment`. A `true` result proves the served set is
/// the complete, untampered filter-matched set the chain attests to.
pub fn verify_served_events(commitment: [u8; 32], block_number: u64, matched_logs: &[Log]) -> bool {
    canonical_event_set_hash(block_number, matched_logs) == commitment
}

/// One filter-matched log as the indexer serves it on
/// `/completeness/{subgrove}/{block}/matched-logs`.
///
/// The wire shape carries the full Ethereum log (block/tx fields, indices,
/// `removed`), but only `address`, `topics`, and `data` are bound by the
/// completeness commitment, so those are the only fields deserialized here.
/// All three are `0x`-prefixed hex.
#[derive(Debug, Clone, Deserialize)]
struct ServedLog {
    /// `"0x"` + 40 hex (20 bytes).
    address: String,
    /// Each `"0x"` + 64 hex (32 bytes); `topics[0]` is the event signature.
    topics: Vec<String>,
    /// `"0x"` + even-length hex, possibly `"0x"` for empty data.
    data: String,
}

/// Body of the indexer's `GET /completeness/{subgrove}/{block}/matched-logs`.
#[derive(Debug, Clone, Deserialize)]
struct MatchedLogsResponse {
    matched_logs: Vec<ServedLog>,
}

/// Decode a `0x`-prefixed hex string into exactly `N` bytes.
fn hex_fixed<const N: usize>(s: &str, field: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s))?;
    if bytes.len() != N {
        return Err(WillowError::Validation(format!(
            "{field} is {} bytes, expected {N}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

impl ServedLog {
    /// Reduce a served log to the commitment-bound [`Log`].
    fn into_log(self) -> Result<Log> {
        let address = hex_fixed::<20>(&self.address, "log address")?;
        let topics = self
            .topics
            .iter()
            .map(|t| hex_fixed::<32>(t, "log topic"))
            .collect::<Result<Vec<_>>>()?;
        let data = hex::decode(self.data.strip_prefix("0x").unwrap_or(&self.data))?;
        Ok(Log::new(address, topics, data))
    }
}

/// Parse an indexer `matched-logs` response body into the commitment-bound
/// [`Log`] set, in served order.
///
/// This is the transport-independent core of [`WillowClient::verify_block_completeness`]:
/// callers who already hold the response bytes (or fetch them through their own
/// HTTP path) can re-hash and compare against the on-chain commitment with
/// [`verify_served_events`] directly.
pub fn parse_matched_logs(body: &[u8]) -> Result<Vec<Log>> {
    let parsed: MatchedLogsResponse = serde_json::from_slice(body)?;
    parsed
        .matched_logs
        .into_iter()
        .map(ServedLog::into_log)
        .collect()
}

impl WillowClient {
    /// Verify a block's completeness end to end, without trusting the indexer.
    ///
    /// Fetches the two halves of the completeness check and compares them:
    ///   1. the on-chain anchor — the block's 32-byte `events_commitment`, read
    ///      from chain state via the consensus RPC ([`crate::consensus::ConsensusClient::events_commitment`]),
    ///   2. the indexer's served preimage — the filter-matched log set, from
    ///      `GET {indexer_base}/completeness/{subgrove}/{block}/matched-logs`.
    ///
    /// Returns [`verify_served_events`] of the served set against the anchor.
    ///
    /// A `true` result proves the indexer served the complete, untampered
    /// filter-matched set the chain attests to. Uses the client's existing
    /// consensus RPC client and HTTP client; the GET targets
    /// [`WillowClient::indexer_base_url`] (set via `indexer_url(..)` on the
    /// builder, else the validator API base).
    ///
    /// # Errors
    /// - `Config` if no consensus URL was configured (the anchor is unreadable).
    /// - `NotFound` if the chain has no commitment for the block, or the indexer
    ///   has no retained matched logs / hasn't finalized the block — the block
    ///   is not completeness-verifiable.
    pub async fn verify_block_completeness(
        &self,
        subgrove_id: &str,
        block_number: u64,
    ) -> Result<bool> {
        let consensus = self.consensus_opt().ok_or_else(|| {
            WillowError::Config(
                "verify_block_completeness needs a consensus URL; set consensus_url(..) on the builder"
                    .to_string(),
            )
        })?;

        let commitment = consensus
            .events_commitment(subgrove_id, block_number)
            .await?
            .ok_or_else(|| {
                WillowError::NotFound(format!(
                    "no on-chain events_commitment for {subgrove_id} block {block_number}"
                ))
            })?;

        let url = self.indexer_base_url().join(&format!(
            "completeness/{subgrove_id}/{block_number}/matched-logs"
        ))?;
        let response = self.http_client.get(url).send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(WillowError::NotFound(format!(
                "indexer returned {status} for {subgrove_id} block {block_number} matched-logs"
            )));
        }

        let logs = parse_matched_logs(&bytes)?;
        Ok(verify_served_events(commitment, block_number, &logs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repeat(byte: u8, n: usize) -> Vec<u8> {
        vec![byte; n]
    }

    fn addr(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn topic(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// Vector A — empty matched set at block 0.
    /// Authoritative cross-language gate (matches native `canonical_event_set_hash`).
    #[test]
    fn vector_a_empty_set() {
        let hash = canonical_event_set_hash(0, &[]);
        assert_eq!(
            hex::encode(hash),
            "52089e4c924fbab0475d310d7f74bf8cae542d006a45d3c5d94adacda6937da5"
        );
    }

    /// Vector B — two logs at block 7.
    /// Authoritative cross-language gate (matches native `canonical_event_set_hash`).
    #[test]
    fn vector_b_two_logs() {
        let logs = vec![
            Log::new(
                addr(0x42),
                vec![topic(0xdd), topic(0x11)],
                vec![0x01, 0x02, 0x03, 0x04],
            ),
            Log::new(addr(0x43), vec![topic(0xaa)], Vec::new()),
        ];
        let hash = canonical_event_set_hash(7, &logs);
        assert_eq!(
            hex::encode(hash),
            "e1544ae919458663e8fce14bdcd06df6a777410c068302c0584dff1587524dfd"
        );
    }

    #[test]
    fn verify_served_events_accepts_matching_commitment() {
        let logs = vec![Log::new(addr(0x42), vec![topic(0xdd)], repeat(0xff, 3))];
        let commitment = canonical_event_set_hash(7, &logs);
        assert!(verify_served_events(commitment, 7, &logs));
    }

    /// A tampered served set — flipped/dropped/added log or wrong block — must
    /// fail to verify against the honest commitment.
    #[test]
    fn verify_served_events_rejects_tampering() {
        let logs = vec![
            Log::new(addr(0x42), vec![topic(0xdd), topic(0x11)], vec![1, 2, 3, 4]),
            Log::new(addr(0x43), vec![topic(0xaa)], Vec::new()),
        ];
        let commitment = canonical_event_set_hash(7, &logs);

        // Honest set still verifies.
        assert!(verify_served_events(commitment, 7, &logs));

        // Wrong block number.
        assert!(!verify_served_events(commitment, 8, &logs));

        // Flipped a data byte in the first log.
        let mut flipped = logs.clone();
        flipped[0].data[0] ^= 0x01;
        assert!(!verify_served_events(commitment, 7, &flipped));

        // Changed a topic in the second log.
        let mut retopic = logs.clone();
        retopic[1].topics[0] = topic(0xbb);
        assert!(!verify_served_events(commitment, 7, &retopic));

        // Dropped a log.
        let dropped = vec![logs[0].clone()];
        assert!(!verify_served_events(commitment, 7, &dropped));

        // Added a log.
        let mut added = logs.clone();
        added.push(Log::new(addr(0x44), vec![], Vec::new()));
        assert!(!verify_served_events(commitment, 7, &added));

        // Reordered the set (commitment binds order).
        let reordered = vec![logs[1].clone(), logs[0].clone()];
        assert!(!verify_served_events(commitment, 7, &reordered));
    }

    /// The on-chain commitment for the `MATCHED_LOGS_FIXTURE` block (Vector B).
    const FIXTURE_COMMITMENT_HEX: &str =
        "e1544ae919458663e8fce14bdcd06df6a777410c068302c0584dff1587524dfd";

    /// Authoritative `GET /completeness/sg/7/matched-logs` body — the
    /// cross-language gate for the JSON -> [`Log`] parse. Same two logs as
    /// Vector B, carrying the full served-log shape (block/tx fields, indices,
    /// `removed`) that the parse must ignore.
    const MATCHED_LOGS_FIXTURE: &str = r#"{
        "subgrove_id": "sg", "block_number": 7, "count": 2,
        "matched_logs": [
          { "block_number": 7, "block_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "transaction_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "transaction_index": 0, "log_index": "0x0",
            "address": "0x4242424242424242424242424242424242424242",
            "topics": ["0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                       "0x1111111111111111111111111111111111111111111111111111111111111111"],
            "data": "0x01020304", "removed": false },
          { "block_number": 7, "block_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "transaction_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "transaction_index": 0, "log_index": "0x1",
            "address": "0x4343434343434343434343434343434343434343",
            "topics": ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "data": "0x", "removed": false } ]
      }"#;

    fn fixture_commitment() -> [u8; 32] {
        let bytes = hex::decode(FIXTURE_COMMITMENT_HEX).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    /// Gate: parsing the authoritative matched-logs body yields a [`Log`] set
    /// whose canonical hash equals the on-chain commitment. This pins the
    /// `{address, topics, data}` JSON -> [`Log`] mapping against the same vector
    /// the native chain hashes.
    #[test]
    fn parse_matched_logs_matches_authoritative_vector() {
        let logs = parse_matched_logs(MATCHED_LOGS_FIXTURE.as_bytes()).unwrap();

        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].address, addr(0x42));
        assert_eq!(logs[0].topics, vec![topic(0xdd), topic(0x11)]);
        assert_eq!(logs[0].data, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(logs[1].address, addr(0x43));
        assert_eq!(logs[1].topics, vec![topic(0xaa)]);
        assert!(logs[1].data.is_empty());

        assert!(verify_served_events(fixture_commitment(), 7, &logs));
    }
}

#[cfg(test)]
mod wrapper_tests {
    use super::*;
    use crate::client::WillowClient;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const COMMITMENT_HEX: &str = "e1544ae919458663e8fce14bdcd06df6a777410c068302c0584dff1587524dfd";

    const MATCHED_LOGS_BODY: &str = r#"{
        "subgrove_id": "sg", "block_number": 7, "count": 2,
        "matched_logs": [
          { "block_number": 7, "block_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "transaction_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "transaction_index": 0, "log_index": "0x0",
            "address": "0x4242424242424242424242424242424242424242",
            "topics": ["0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                       "0x1111111111111111111111111111111111111111111111111111111111111111"],
            "data": "0x01020304", "removed": false },
          { "block_number": 7, "block_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "transaction_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "transaction_index": 0, "log_index": "0x1",
            "address": "0x4343434343434343434343434343434343434343",
            "topics": ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "data": "0x", "removed": false } ]
      }"#;

    /// JSON body of a successful ABCI `abci_query` for the events_commitment
    /// anchor: `response.code == 0`, `response.value` = base64 of the anchor
    /// JSON (which itself carries the commitment as 64-hex).
    fn anchor_rpc_body() -> serde_json::Value {
        use base64::Engine;
        let anchor = serde_json::json!({
            "subgrove_id": "sg",
            "block_number": 7,
            "events_commitment": COMMITMENT_HEX,
        });
        let value_b64 =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&anchor).unwrap());
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "response": { "code": 0, "value": value_b64 } }
        })
    }

    /// Full e2e: the anchor RPC returns the commitment and the indexer GET
    /// returns the authoritative matched-logs body. `verify_block_completeness`
    /// must fetch both through the SDK's real transports and return `true`.
    #[tokio::test]
    async fn verify_block_completeness_true_against_mocked_transports() {
        let server = MockServer::start().await;

        // Consensus RPC: abci_query for the anchor (POST, JSON-RPC).
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(anchor_rpc_body()))
            .mount(&server)
            .await;

        // Indexer GET: matched-logs preimage.
        Mock::given(method("GET"))
            .and(path("/completeness/sg/7/matched-logs"))
            .respond_with(ResponseTemplate::new(200).set_body_string(MATCHED_LOGS_BODY))
            .mount(&server)
            .await;

        // One server backs both the validator API/indexer base and the
        // consensus RPC, so both mocked routes are reachable.
        let client = WillowClient::builder()
            .api_url(&server.uri())
            .consensus_url(&server.uri())
            .build()
            .await
            .unwrap();

        assert!(client.verify_block_completeness("sg", 7).await.unwrap());
    }

    /// A non-zero ABCI code (no commitment for the block) surfaces as
    /// not-verifiable (`NotFound`), not a silent `false`.
    #[tokio::test]
    async fn verify_block_completeness_no_anchor_is_not_found() {
        let server = MockServer::start().await;

        let no_anchor = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "response": { "code": 1, "log": "No events commitment for block 7" } }
        });
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(no_anchor))
            .mount(&server)
            .await;

        let client = WillowClient::builder()
            .api_url(&server.uri())
            .consensus_url(&server.uri())
            .build()
            .await
            .unwrap();

        let err = client.verify_block_completeness("sg", 7).await.unwrap_err();
        assert!(matches!(err, WillowError::NotFound(_)), "got {err:?}");
    }
}
