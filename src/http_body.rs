//! Caps on the size of the answers the SDK reads, one per kind of answer.
//!
//! The SDK reads an answer's body a piece at a time and stops once it passes the cap of its
//! route, refusing it with [`WillowError::ResponseTooLarge`] before decoding any of it (an
//! answer that declares a longer length is refused before any is read), so a server can't make
//! it hold an answer of any size. Such an answer is not retried.
//!
//! A cap bounds the bytes read, not the memory decoding them takes, which can be a multiple of
//! it: a JSON list of empty objects or arrays decodes to tens of bytes per element. So before
//! decoding an answer into a type that holds `serde_json::Value`s, the SDK counts what it holds
//! ([`check_json`]) and refuses one past [`MAX_VALUES`] units with
//! [`WillowError::ResponseTooComplex`].
//!
//! Each cap is the smallest that holds the largest honest answer of its routes where the node
//! bounds that answer. Where the request sets an answer's size (a query's limit) and the node
//! sets no maximum, the cap is [`LARGE`], and an answer past it is refused: ask for less.

use crate::errors::{Result, WillowError};
use serde::de::DeserializeOwned;

/// Answers of a fixed shape: health, root hashes, a value read by key (`/data`, at most what
/// one transaction writes), an account's nonce, balances, the token's information, the fee
/// schedule, a DID document, one subgrove, validator, or indexer, checkpoint roots, a file's
/// manifest and a page of the file list (at most 100 files), ERC-8004 answers (at most 100
/// entries), and CometBFT's `status`, `commit`, `validators` (at most 100 a page),
/// `abci_query`, and `broadcast_tx_sync`. These are a few KiB; 4 MiB is the chain's
/// `max_tx_bytes`, the most one transaction writes.
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

/// The lists the API doesn't page (subgroves, validators, indexers, a subgrove's key grants, a
/// DID's permissions), which grow with the chain: the chain bounds no data or file subgrove's
/// schema or access lists, so one registration can fill a transaction and any account can push
/// a list past 4 MiB. And answers whose size the request sets, with no maximum on the node: a
/// `/query` page (100
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

/// The most JSON the SDK decodes of one answer into a type holding `serde_json::Value`s, in
/// units: each string, number, `true`, `false`, or `null` costs one, and each array or object
/// [`CONTAINER_COST`]. Decoded, a `Value` takes 32 bytes and a container a few hundred with its
/// first member, so an answer under the limit decodes to at most a few hundred MiB. An honest
/// answer holds far fewer: a page of 100 documents of 10 fields is under 3,000.
pub const MAX_VALUES: usize = 1 << 21;

/// What an array or object costs (see [`MAX_VALUES`]).
pub const CONTAINER_COST: usize = 8;

/// How many numbers under a SQL or GraphQL answer's top-level `proof` cost one unit: the SDK
/// decodes that proof into typed fields (`Vec<u8>` byte arrays), where a number takes a byte
/// and one of another kind fails the decode at once.
const PROOF_NUMBERS_PER_UNIT: usize = 16;

/// Which numbers in an answer cost less than a unit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum JsonBudget {
    /// Every number costs one: the answer may decode into `Value`s.
    Full,
    /// A number under the answer's top-level `proof` costs a sixteenth (see
    /// [`PROOF_NUMBERS_PER_UNIT`]): a SQL or GraphQL answer, which an indexer sends with a proof
    /// of every row.
    UnderProof,
}

/// Refuses with [`WillowError::ResponseTooComplex`] an answer that holds more than
/// [`MAX_VALUES`] units under `budget`, without decoding it: one pass, no allocation. It
/// doesn't validate the JSON; the decoder refuses what isn't valid.
pub(crate) fn check_json(data: &[u8], budget: JsonBudget) -> Result<()> {
    if scan_units(data, MAX_VALUES, budget) {
        Ok(())
    } else {
        Err(WillowError::ResponseTooComplex { limit: MAX_VALUES })
    }
}

/// Whether `data` holds at most `max` units under `budget`.
fn scan_units(data: &[u8], max: usize, budget: JsonBudget) -> bool {
    let (mut units, mut depth, mut cheap) = (0usize, 0usize, 0usize);
    let mut under_proof = false;
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'"' => {
                units += 1;
                let start = i + 1;
                i += 1;
                while i < data.len() && data[i] != b'"' {
                    if data[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if budget == JsonBudget::UnderProof
                    && depth == 1
                    && data.get(start..i) == Some(&b"proof"[..])
                    && opens_container_after_colon(data, i + 1)
                {
                    under_proof = true;
                }
            }
            b'[' | b'{' => {
                units += CONTAINER_COST;
                depth += 1;
            }
            b']' | b'}' => {
                depth = depth.saturating_sub(1);
                if depth <= 1 {
                    under_proof = false;
                }
            }
            b'-' | b'0'..=b'9' => {
                if under_proof {
                    cheap += 1;
                    if cheap == PROOF_NUMBERS_PER_UNIT {
                        units += 1;
                        cheap = 0;
                    }
                } else {
                    units += 1;
                }
                while i + 1 < data.len() && is_scalar_byte(data[i + 1]) {
                    i += 1;
                }
            }
            b'a'..=b'z' => {
                units += 1;
                while i + 1 < data.len() && is_scalar_byte(data[i + 1]) {
                    i += 1;
                }
            }
            _ => {}
        }
        if units > max {
            return false;
        }
        i += 1;
    }
    true
}

fn is_scalar_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'-')
}

/// Whether `data` at `i` is a colon and then an array or object, whitespace aside.
fn opens_container_after_colon(data: &[u8], mut i: usize) -> bool {
    let skip = |i: &mut usize| {
        while *i < data.len() && matches!(data[*i], b' ' | b'\t' | b'\n' | b'\r') {
            *i += 1;
        }
    };
    skip(&mut i);
    if data.get(i) != Some(&b':') {
        return false;
    }
    i += 1;
    skip(&mut i);
    matches!(data.get(i), Some(b'[' | b'{'))
}

/// `text` decoded from JSON after [`check_json`] under `budget`.
pub(crate) fn decode_checked<T: DeserializeOwned>(text: &str, budget: JsonBudget) -> Result<T> {
    check_json(text.as_bytes(), budget)?;
    serde_json::from_str(text).map_err(WillowError::Serialization)
}

#[cfg(test)]
mod json_budget_tests {
    use super::*;

    fn numbers(n: usize) -> String {
        vec!["0"; n].join(",")
    }

    #[test]
    fn units_are_counted_as_documented() {
        for (json, units) in [
            ("0", 1),
            ("\"a\"", 1),
            ("[]", CONTAINER_COST),
            ("{\"a\":1,\"b\":[]}", 2 * CONTAINER_COST + 3),
            ("[\"[{,\\\"]}\", true, null]", CONTAINER_COST + 3),
        ] {
            assert!(
                scan_units(json.as_bytes(), units, JsonBudget::Full),
                "{json} at {units}"
            );
            assert!(
                !scan_units(json.as_bytes(), units - 1, JsonBudget::Full),
                "{json} at {}",
                units - 1
            );
        }
    }

    #[test]
    fn a_list_of_containers_or_numbers_past_the_limit_is_refused() {
        let objects = format!(
            "[{}]",
            vec!["{}"; MAX_VALUES / CONTAINER_COST + 1].join(",")
        );
        assert!(matches!(
            check_json(objects.as_bytes(), JsonBudget::Full),
            Err(WillowError::ResponseTooComplex { .. })
        ));
        let flat = format!("[{}]", numbers(MAX_VALUES));
        assert!(check_json(flat.as_bytes(), JsonBudget::Full).is_err());
        // Numbers in rows count even in a SQL answer; under its proof they cost a sixteenth.
        let rows = format!("{{\"rows\":[[{}]]}}", numbers(MAX_VALUES));
        assert!(check_json(rows.as_bytes(), JsonBudget::UnderProof).is_err());
        let proof = format!(
            "{{\"rows\":[],\"proof\":{{\"state_root\":[{}]}}}}",
            numbers(MAX_VALUES)
        );
        assert!(check_json(proof.as_bytes(), JsonBudget::UnderProof).is_ok());
        let nested = format!("{{\"rows\":[[{{\"proof\":[{}]}}]]}}", numbers(MAX_VALUES));
        assert!(check_json(nested.as_bytes(), JsonBudget::UnderProof).is_err());
    }
}
