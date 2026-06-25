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

// Optional convenience: `verify_block_completeness(subgrove_id, block_number)`.
//
// The byte-level core above is the SDK's contribution to willow PR #676. A
// fetch-and-verify wrapper would:
//   1. read the anchor — the validator ABCI store query for the block's
//      `events_commitment` (CometBFT `abci_query`, like
//      `ConsensusClient::next_nonce_via_rpc`),
//   2. read the preimage — the indexer's served matched-log set
//      (`GET {indexer_base}/completeness/{subgrove}/{block}/matched-logs`,
//      mapped to `[Log]`),
//   3. return `verify_served_events(commitment, block_number, &logs)`.
//
// It is intentionally NOT implemented here: neither the `events_commitment`
// ABCI store path nor the indexer `/completeness/.../matched-logs` route exists
// on the server side yet (they ship with the rest of PR #676). Wiring against an
// unverified, non-existent endpoint shape would be speculative; the wrapper
// lands once those endpoints are merged and their exact response shapes are
// pinned. Callers can compose the three steps today using the existing consensus
// RPC and indexer HTTP clients plus `verify_served_events`.

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
}
