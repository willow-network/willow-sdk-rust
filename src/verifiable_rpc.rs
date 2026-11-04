//! Client-side verifiable RPC: query an indexer and verify locally.
//!
//! This module is the SDK counterpart to the `GET /verifiable-rpc/:subgrove/:key`
//! endpoint implemented by the indexer node. On each response it checks:
//!
//!  1. **GroveDB Merkle proof** — that `answer` is the Item at `key` in one
//!     entity tree of the subgrove (`[subgroves, subgrove, indexed, <entity>]`),
//!     in the tree rooted at the response's `state_root`
//!     ([`crate::grovedb_envelope::verify_item_at_path`]). An absent answer
//!     can't be checked (the indexer proves absence under one entity only), so
//!     it is refused in the verifying modes.
//!  2. **GKR proof** (strict mode) — that `state_root` is the output of the
//!     subgrove's transformation over the events the proof commits to.
//!     `GKR_PROOF_FULL` is verified locally via `willow-gkr-verify`; circuit
//!     bytes are embedded at build time via the `registry` feature.
//!
//! **The answer is not verified against the chain.** `state_root` is the
//! indexer's own claim, carried in the same response: nothing here anchors it
//! to a root the SDK trusts (consensus, or an Ethereum light client for the
//! events), so an indexer can serve any state root with proofs that match it.
//! [`VerifiedAnswer::state_root_anchored`] is always `false`.
//!
//! This module is gated behind the `verifiable-rpc` cargo feature because
//! it adds new public surface (state-root continuity tracking,
//! verification policy). Users who don't need verifiable RPC don't pay
//! the surface cost.
//!
//! # State continuity
//!
//! The client caches the last-seen `state_root` per subgrove. Two basic
//! checks run on every response:
//!
//! - **Non-regression**: a later response whose `block_range.1` is strictly
//!   less than the cached one is rejected — an honest indexer never
//!   advances backward.
//! - **Consistency at the same tip**: a response with the same
//!   `block_range.1` as the cache but a *different* `state_root` is
//!   rejected — two state roots for the same block range is a fork.
//!
//! A client that wants hard TOFU (trust-on-first-use) semantics beyond the
//! first observation should layer its own anchoring (e.g., fetch the
//! consensus state root for the subgrove once and compare against the
//! first response).

use crate::client::{SeenStateRoot, VerifyMode, WillowClient};
use crate::errors::{Result, WillowError};
use std::time::{SystemTime, UNIX_EPOCH};
use willow_gkr_verify::FULL_HEADER;
use willow_types::consensus::indexing_transactions::GkrProofData;
use willow_types::verifiable_rpc::VerifiableRpcResponse;

/// Answer returned by [`VerifiableRpcOperations::query`]: the indexer's answer,
/// checked only against the response's own `state_root` (see the module notes).
///
/// `verification` records exactly which checks passed, so callers can branch on
/// that rather than guessing from `answer` alone.
#[derive(Debug, Clone)]
pub struct VerifiedAnswer {
    /// The value at the key. `None` only with [`VerifyMode::Disabled`], where it
    /// is the indexer's word that the key is absent.
    pub answer: Option<Vec<u8>>,
    /// State root the proofs tie back to: the indexer's claim.
    pub state_root: [u8; 32],
    /// Block range covered by the checkpoint that produced `state_root`.
    pub block_range: (u64, u64),
    /// Which checks passed.
    pub verification: VerificationResult,
    /// Whether `state_root` was checked against a root the SDK trusts: always
    /// `false`, so `answer` is unverified against the chain.
    pub state_root_anchored: bool,
}

/// Which checks a verifiable-RPC response passed. None anchors `state_root`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// The GroveDB proof binds `answer` at the key under `state_root`, and the
    /// GKR proofs verify and chain to `state_root`.
    GkrAndGroveDb,
    /// The GroveDB proof binds `answer` at the key under `state_root`
    /// ([`VerifyMode::GroveDbOnly`]).
    GroveDbOnly,
    /// Nothing was checked: the client is in [`VerifyMode::Disabled`].
    Skipped,
}

/// SDK-side operations for verifiable RPC.
///
/// Construct via [`WillowClient::verifiable_rpc`]. Cheap to create —
/// state-root cache lives on the client.
pub struct VerifiableRpcOperations {
    client: WillowClient,
}

impl VerifiableRpcOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self { client }
    }

    /// Query a subgrove for the value at `key`, checking the response locally
    /// according to the client's [`VerifyMode`].
    ///
    /// The answer is unverified against the chain: the checks tie it to the
    /// response's own `state_root`, which the SDK does not anchor (see the module
    /// notes). In the checking modes, an answer the indexer reports absent is
    /// refused ([`WillowError::Unsupported`]): its absence proof covers one
    /// entity tree, not the subgrove.
    pub async fn query(&self, subgrove_id: &str, key: &[u8]) -> Result<VerifiedAnswer> {
        let raw = self.query_raw(subgrove_id, key).await?;

        let mode = self.client.verify_mode();

        // Continuity check runs regardless of mode — it's a cross-response
        // sanity check, not a proof verification. An indexer that serves
        // backward-moving state roots is broken, period.
        self.check_continuity(subgrove_id, &raw)?;

        let verification = match mode {
            VerifyMode::Disabled => VerificationResult::Skipped,
            VerifyMode::GroveDbOnly => {
                verify_grovedb_proof(&raw, subgrove_id, key)?;
                VerificationResult::GroveDbOnly
            }
            VerifyMode::Strict => {
                verify_grovedb_proof(&raw, subgrove_id, key)?;
                if raw.gkr_proofs.is_empty() {
                    return Err(WillowError::ProofVerificationFailed(
                        "Strict verify mode: indexer returned no GKR proofs".into(),
                    ));
                }
                // Verify each chunk's proof. The final chunk's
                // output_root must equal `state_root` (the block's
                // settled state); intermediate chunks chain to the
                // next chunk's `starting_state_root`.
                for (i, proof) in raw.gkr_proofs.iter().enumerate() {
                    let expected_root = if i + 1 == raw.gkr_proofs.len() {
                        raw.state_root
                    } else {
                        raw.gkr_proofs[i + 1].public_inputs.starting_state_root
                    };
                    verify_gkr_proof(proof, expected_root)?;
                }
                VerificationResult::GkrAndGroveDb
            }
        };

        self.record_seen_root(subgrove_id, &raw);

        let answer = if raw.answer_exists {
            Some(raw.answer.clone())
        } else {
            None
        };

        Ok(VerifiedAnswer {
            answer,
            state_root: raw.state_root,
            block_range: raw.block_range,
            verification,
            state_root_anchored: false,
        })
    }

    /// Fetch the raw response without verifying anything. Exposed for
    /// callers who want custom verification logic or debugging.
    pub async fn query_raw(&self, subgrove_id: &str, key: &[u8]) -> Result<VerifiableRpcResponse> {
        let hex_key = hex::encode(key);
        let path = format!("verifiable-rpc/{}/{}", subgrove_id, hex_key);
        let url = self
            .client
            .require_indexer_url()?
            .join(&path)
            .map_err(|e| WillowError::Config(format!("invalid verifiable-rpc URL: {}", e)))?;

        let resp = self.client.http_client.get(url).send().await?;
        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            return Err(WillowError::Http {
                status: status.as_u16(),
                message: body,
            });
        }

        serde_json::from_str::<VerifiableRpcResponse>(&body).map_err(WillowError::Serialization)
    }

    /// The state root this client last observed for a subgrove, if any.
    pub fn last_seen_root(&self, subgrove_id: &str) -> Option<SeenStateRoot> {
        self.client
            .state_root_cache
            .read()
            .unwrap()
            .get(subgrove_id)
            .cloned()
    }

    /// Drop the state-root cache (e.g., when switching indexers).
    pub fn clear_root_cache(&self) {
        self.client.state_root_cache.write().unwrap().clear();
    }

    fn check_continuity(&self, subgrove_id: &str, resp: &VerifiableRpcResponse) -> Result<()> {
        let cache = self.client.state_root_cache.read().unwrap();
        let Some(prev) = cache.get(subgrove_id) else {
            return Ok(());
        };

        // Same tip but different root = fork.
        if prev.block_range.1 == resp.block_range.1 && prev.state_root != resp.state_root {
            return Err(WillowError::ProofVerificationFailed(format!(
                "state-root fork on subgrove '{}' at block {}: expected {}, got {}",
                subgrove_id,
                resp.block_range.1,
                hex::encode(prev.state_root),
                hex::encode(resp.state_root),
            )));
        }

        // Tip moved backwards: stale indexer.
        if resp.block_range.1 < prev.block_range.1 {
            return Err(WillowError::ProofVerificationFailed(format!(
                "subgrove '{}' regressed: last seen tip at block {}, new response at block {}",
                subgrove_id, prev.block_range.1, resp.block_range.1
            )));
        }

        Ok(())
    }

    fn record_seen_root(&self, subgrove_id: &str, resp: &VerifiableRpcResponse) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let entry = SeenStateRoot {
            state_root: resp.state_root,
            block_range: resp.block_range,
            checkpoint_id: resp.checkpoint_id,
            observed_at_unix_secs: now,
        };
        self.client
            .state_root_cache
            .write()
            .unwrap()
            .insert(subgrove_id.to_string(), entry);
    }
}

/// Check that the response's GroveDB proof proves `resp.answer` as the Item at
/// `key` in one entity tree of the subgrove, `[subgroves, subgrove, indexed,
/// <entity>]` (the path the proof descends), under `resp.state_root`. The
/// response must be for `subgrove_id` and `key`.
fn verify_grovedb_proof(resp: &VerifiableRpcResponse, subgrove_id: &str, key: &[u8]) -> Result<()> {
    let fail = |m: String| WillowError::ProofVerificationFailed(m);
    if resp.grovedb_proof.is_empty() {
        return Err(fail("GroveDB proof is empty".into()));
    }
    if resp.subgrove_id != subgrove_id || resp.key != key {
        return Err(fail(
            "the response is for another subgrove or key than the one asked".into(),
        ));
    }
    if !resp.answer_exists {
        return Err(WillowError::Unsupported(
            "an absent answer can't be checked: the indexer proves absence under one entity \
             tree, not the subgrove"
                .into(),
        ));
    }
    let path = crate::grovedb_envelope::descended_path(&resp.grovedb_proof)?;
    let entity_tree = path.len() == 4
        && path[0] == b"subgroves"
        && path[1] == subgrove_id.as_bytes()
        && path[2] == b"indexed";
    if !entity_tree {
        return Err(fail(
            "the proof is not of an entity tree of the subgrove asked".into(),
        ));
    }
    let (root, item) =
        crate::grovedb_envelope::verify_item_at_path(&resp.grovedb_proof, &path, key)?;
    if item != resp.answer {
        return Err(fail(
            "the answer is not the item the proof proves at the key".into(),
        ));
    }
    if root != resp.state_root {
        return Err(fail(format!(
            "GroveDB proof root {} does not match response state_root {}",
            hex::encode(root),
            hex::encode(resp.state_root),
        )));
    }
    Ok(())
}

/// Verify the GKR proof carried in a verifiable-RPC response.
///
/// Cross-checks the proof's claimed `output_root` against the response's
/// `state_root`, then verifies the `GKR_PROOF_FULL` payload via the
/// pure-Rust verifier (compiles to wasm32; circuit bytes embedded at
/// compile time via `willow_gkr_verify::registry`).
fn verify_gkr_proof(proof: &GkrProofData, expected_state_root: [u8; 32]) -> Result<()> {
    if proof.public_inputs.output_root != expected_state_root {
        return Err(WillowError::ProofVerificationFailed(format!(
            "GKR proof output_root {} does not match response state_root {}",
            hex::encode(proof.public_inputs.output_root),
            hex::encode(expected_state_root),
        )));
    }

    if proof.proof.len() < FULL_HEADER.len() || &proof.proof[..FULL_HEADER.len()] != FULL_HEADER {
        return Err(WillowError::ProofVerificationFailed(
            "GKR proof header is not GKR_PROOF_FULL".into(),
        ));
    }

    verify_full(proof)
}

/// Full-GKR verification — pure-Rust verifier (`willow-gkr-verify`).
/// No Expander in the dep graph; compiles to `wasm32-unknown-unknown`.
/// Cross-validated byte-for-byte against the native Expander verifier
/// via fixtures.
fn verify_full(proof: &GkrProofData) -> Result<()> {
    willow_gkr_verify::verify_full_proof_with_registry(
        &proof.proof,
        &proof.public_inputs,
        proof.verification_key_hash,
    )
    .map_err(|e| WillowError::ProofVerificationFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::WillowClient;
    use willow_gkr_verify::FULL_HEADER;
    use willow_types::consensus::indexing_transactions::{GkrProofData, GkrPublicInputs};
    use willow_types::consensus::CURRENT_PROOF_VERSION;

    fn mk_response(state_root: [u8; 32], tip: u64) -> VerifiableRpcResponse {
        VerifiableRpcResponse {
            subgrove_id: "sg".into(),
            key: vec![1, 2, 3],
            answer: vec![4, 5, 6],
            answer_exists: true,
            checkpoint_id: [0; 32],
            state_root,
            block_range: (tip.saturating_sub(100), tip),
            grovedb_proof: vec![0xaa; 64],
            gkr_proofs: vec![GkrProofData {
                proof_version: CURRENT_PROOF_VERSION,
                proof: vec![0xbb; 64],
                public_inputs: GkrPublicInputs {
                    output_root: state_root,
                    block_range: (tip.saturating_sub(100), tip),
                    config_hash: [2; 32],
                    starting_state_root: [0; 32],
                },
                verification_key_hash: [3; 32],
                proof_size_bytes: 64,
                generation_time_ms: 1,
                gpu_accelerated: false,
            }],
            completeness_proof: None,
            state_proofs: Vec::new(),
            served_at_unix_secs: 1_700_000_000,
        }
    }

    async fn test_client() -> WillowClient {
        WillowClient::builder()
            .api_url("http://127.0.0.1:1")
            .build()
            .await
            .expect("build client")
    }

    #[tokio::test]
    async fn continuity_detects_fork() {
        let client = test_client().await;
        let ops = VerifiableRpcOperations::new(client);

        let first = mk_response([1; 32], 500);
        ops.record_seen_root("sg", &first);

        // Same tip, different root → fork.
        let fork = mk_response([2; 32], 500);
        let err = ops
            .check_continuity("sg", &fork)
            .expect_err("fork must be rejected");
        assert!(err.to_string().contains("fork"));
    }

    #[tokio::test]
    async fn continuity_detects_regression() {
        let client = test_client().await;
        let ops = VerifiableRpcOperations::new(client);

        let first = mk_response([1; 32], 500);
        ops.record_seen_root("sg", &first);

        // Tip moved backward → regression.
        let older = mk_response([3; 32], 400);
        let err = ops
            .check_continuity("sg", &older)
            .expect_err("regression must be rejected");
        assert!(err.to_string().contains("regressed"));
    }

    #[tokio::test]
    async fn continuity_allows_forward_progress() {
        let client = test_client().await;
        let ops = VerifiableRpcOperations::new(client);

        let first = mk_response([1; 32], 500);
        ops.record_seen_root("sg", &first);

        // Advancing tip with a new root is fine.
        let next = mk_response([2; 32], 600);
        ops.check_continuity("sg", &next)
            .expect("forward progress must be accepted");
    }

    #[tokio::test]
    async fn continuity_allows_same_root_same_tip() {
        let client = test_client().await;
        let ops = VerifiableRpcOperations::new(client);

        let first = mk_response([1; 32], 500);
        ops.record_seen_root("sg", &first);

        // Same tip, same root → idempotent re-read.
        let again = mk_response([1; 32], 500);
        ops.check_continuity("sg", &again)
            .expect("idempotent re-read must be accepted");
    }

    #[test]
    fn verify_gkr_proof_rejects_mismatched_root() {
        let proof = GkrProofData {
            proof_version: CURRENT_PROOF_VERSION,
            proof: vec![0; 64],
            public_inputs: GkrPublicInputs {
                output_root: [7; 32],
                block_range: (0, 10),
                config_hash: [0; 32],
                starting_state_root: [0; 32],
            },
            verification_key_hash: [0; 32],
            proof_size_bytes: 64,
            generation_time_ms: 0,
            gpu_accelerated: false,
        };

        let err =
            verify_gkr_proof(&proof, [8; 32]).expect_err("mismatched output_root must be rejected");
        assert!(err.to_string().contains("output_root"));
    }

    /// A full proof with an unknown circuit-version hash has no
    /// embedded VK bytes and surfaces a "missing circuit bytes" error.
    /// With a matching hash but garbage payload it fails deserialization
    /// or cryptographic verification, surfacing one of the upstream errors.
    #[test]
    fn verify_gkr_proof_full_rejects_unknown_circuit() {
        let pi = GkrPublicInputs {
            output_root: [2; 32],
            block_range: (0, 1),
            config_hash: [3; 32],
            starting_state_root: [0; 32],
        };
        let mut full_proof = FULL_HEADER.to_vec();
        full_proof.extend_from_slice(&[0u8; 200]);
        let data = GkrProofData {
            proof_version: CURRENT_PROOF_VERSION,
            proof: full_proof,
            public_inputs: pi.clone(),
            verification_key_hash: [0x55; 32], // not an embedded circuit
            proof_size_bytes: 0,
            generation_time_ms: 0,
            gpu_accelerated: false,
        };
        let err =
            verify_gkr_proof(&data, pi.output_root).expect_err("unknown circuit must be rejected");
        assert!(
            err.to_string().contains("circuit_bytes"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn verify_gkr_proof_rejects_unknown_format() {
        let pi = GkrPublicInputs {
            output_root: [2; 32],
            block_range: (0, 1),
            config_hash: [3; 32],
            starting_state_root: [0; 32],
        };
        let data = GkrProofData {
            proof_version: CURRENT_PROOF_VERSION,
            proof: b"SOME_OTHER_FORMAT_....................................".to_vec(),
            public_inputs: pi.clone(),
            verification_key_hash: [0; 32],
            proof_size_bytes: 0,
            generation_time_ms: 0,
            gpu_accelerated: false,
        };
        let err =
            verify_gkr_proof(&data, pi.output_root).expect_err("unknown format must be rejected");
        assert!(err.to_string().contains("not GKR_PROOF_FULL"));
    }

    #[test]
    fn verify_grovedb_rejects_empty_proof() {
        let mut resp = mk_response([0; 32], 0);
        resp.grovedb_proof.clear();
        let err = verify_grovedb_proof(&resp, "sg", &resp.key.clone())
            .expect_err("empty proof must be rejected");
        assert!(err.to_string().contains("empty"));
    }

    /// A real proof over `[subgroves, aave-v3-lending, indexed, Supply]`, one key, as the
    /// indexer serves it: the response's root and the item at the key.
    fn fixture_response() -> VerifiableRpcResponse {
        let b = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/grovedb-single-key.bin"
        ))
        .unwrap();
        let mut o = 8;
        let u = |o: &mut usize| {
            let v = u64::from_le_bytes(b[*o..*o + 8].try_into().unwrap());
            *o += 8;
            v as usize
        };
        let root: [u8; 32] = b[o..o + 32].try_into().unwrap();
        o += 32;
        let mut path = vec![];
        for _ in 0..u(&mut o) {
            let n = u(&mut o);
            path.push(b[o..o + n].to_vec());
            o += n;
        }
        let n = u(&mut o);
        let query = b[o..o + n].to_vec();
        o += n + 16;
        let n = u(&mut o);
        let proof = b[o..o + n].to_vec();
        let key = query[4..4 + query[3] as usize].to_vec();
        let (_, item) = crate::grovedb_envelope::verify_item_at_path(&proof, &path, &key).unwrap();
        let mut resp = mk_response(root, 500);
        resp.subgrove_id = String::from_utf8(path[1].clone()).unwrap();
        resp.key = key;
        resp.answer = item;
        resp.grovedb_proof = proof;
        resp
    }

    #[test]
    fn the_answer_is_bound_to_the_proof_at_its_key() {
        let resp = fixture_response();
        let sg = resp.subgrove_id.clone();
        let key = resp.key.clone();
        verify_grovedb_proof(&resp, &sg, &key).unwrap();

        // Another answer beside the same proof.
        let mut forged = resp.clone();
        forged.answer = b"forged".to_vec();
        assert!(verify_grovedb_proof(&forged, &sg, &key).is_err());
        // Another subgrove or key than the one asked.
        assert!(verify_grovedb_proof(&resp, "other-sg", &key).is_err());
        assert!(verify_grovedb_proof(&resp, &sg, b"other-key").is_err());
        // Another state root.
        let mut other_root = resp.clone();
        other_root.state_root = [9; 32];
        assert!(verify_grovedb_proof(&other_root, &sg, &key).is_err());
        // An absent answer can't be checked.
        let mut absent = resp.clone();
        absent.answer_exists = false;
        assert!(matches!(
            verify_grovedb_proof(&absent, &sg, &key),
            Err(WillowError::Unsupported(_))
        ));
        // A lone Push(Hash(state_root)) proves nothing.
        let mut lone = resp.clone();
        lone.grovedb_proof = [&[0x00, 0x21, 0x01][..], &resp.state_root, &[0x00, 0x01]].concat();
        assert!(verify_grovedb_proof(&lone, &sg, &key).is_err());
    }
}
