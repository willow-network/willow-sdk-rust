//! Client-side verifiable RPC: query an indexer and verify locally.
//!
//! This module is the SDK counterpart to the `GET /verifiable-rpc/:subgrove/:key`
//! endpoint implemented by `willow-indexer-node`. On each response we run the
//! two proofs side by side:
//!
//!  1. **GKR proof** (if present) — confirms the indexer's claimed
//!     `state_root` is the correct output of transforming committed events.
//!     Phase 1 of the SDK supports the binding-only proof format
//!     (`GKR_PROOF_BINDING_ONLY`), which is self-contained and verifiable
//!     with just SHA-256. Full-soundness GKR proofs (`GKR_PROOF_FULL`)
//!     require the Expander stack and will be supported in a follow-up
//!     when a thin verification crate or build patches are in place — for
//!     now `query()` rejects them in `Strict` mode rather than silently
//!     passing them.
//!  2. **GroveDB Merkle proof** — confirms `answer` is the value at `key`
//!     in the tree rooted at `state_root`. Verified via GroveDB's
//!     lightweight verify-only mode (already shipped with the SDK).
//!
//! Together these two proofs are equivalent to re-executing indexing from
//! raw Ethereum events — modulo *event authenticity*, which is the client's
//! responsibility via its Ethereum light client (already integrated; see
//! [`crate::light_client`]).
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
use grovedb::{GroveDb, PathQuery, Query};
use grovedb_version::version::GroveVersion;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use willow_types::consensus::indexing_transactions::{GkrProofData, GkrPublicInputs};
use willow_types::verifiable_rpc::VerifiableRpcResponse;

/// Header bytes prefixing every binding-only proof produced by
/// `willow-gkr`'s prover (`generate_binding_only_proof`). Kept in sync
/// with `crates/gkr/src/verifier.rs::verify_binding_proof`.
const BINDING_HEADER: &[u8] = b"GKR_PROOF_BINDING_ONLY";
/// Header bytes for full GKR proofs. The SDK's binding-only verifier
/// recognizes these so it can return a precise error rather than failing
/// at the format check.
const FULL_HEADER: &[u8] = b"GKR_PROOF_FULL";
/// Supported binding-only serialization-format version. Bumped only on
/// breaking changes to the byte layout — must stay aligned with
/// `crates/gkr/src/prover.rs`.
const BINDING_FORMAT_VERSION: u8 = 1;

/// Verified answer returned by [`VerifiableRpcOperations::query`].
///
/// `verification` records exactly which guarantees the client was able to
/// establish, so callers can branch on that rather than guessing from
/// `answer` alone.
#[derive(Debug, Clone)]
pub struct VerifiedAnswer {
    /// `Some(bytes)` when the key was present. `None` means the indexer
    /// cryptographically proved the key is absent from the tree.
    pub answer: Option<Vec<u8>>,
    /// State root the proofs tie back to.
    pub state_root: [u8; 32],
    /// Block range covered by the checkpoint that produced `state_root`.
    pub block_range: (u64, u64),
    /// Which guarantees the client established.
    pub verification: VerificationResult,
}

/// Outcome of verification for a verifiable-RPC response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// Both the GKR proof and the GroveDB proof verified.
    GkrAndGroveDb,
    /// The GroveDB proof verified. The GKR proof was not present or the
    /// client was in [`VerifyMode::GroveDbOnly`]. The answer is correct
    /// relative to `state_root` but the client needs an out-of-band anchor
    /// (typically consensus) to trust `state_root` itself.
    GroveDbOnly,
    /// Verification was skipped because the client is in
    /// [`VerifyMode::Disabled`]. Intended for debugging.
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

    /// Query a subgrove for the value at `key`, verifying the response
    /// locally according to the client's [`VerifyMode`].
    ///
    /// Returns [`VerifiedAnswer::answer`] as `None` when the indexer proves
    /// the key is absent.
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
                verify_grovedb_proof(&raw, key)?;
                VerificationResult::GroveDbOnly
            }
            VerifyMode::Strict => {
                verify_grovedb_proof(&raw, key)?;
                match &raw.gkr_proof {
                    Some(proof) => {
                        verify_gkr_proof(proof, raw.state_root)?;
                        VerificationResult::GkrAndGroveDb
                    }
                    None => {
                        return Err(WillowError::ProofVerificationFailed(
                            "Strict verify mode: indexer returned no GKR proof".into(),
                        ));
                    }
                }
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
        })
    }

    /// Fetch the raw response without verifying anything. Exposed for
    /// callers who want custom verification logic or debugging.
    pub async fn query_raw(&self, subgrove_id: &str, key: &[u8]) -> Result<VerifiableRpcResponse> {
        let hex_key = hex::encode(key);
        let path = format!("verifiable-rpc/{}/{}", subgrove_id, hex_key);
        let url = self
            .client
            .indexer_base_url()
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

fn verify_grovedb_proof(resp: &VerifiableRpcResponse, key: &[u8]) -> Result<()> {
    if resp.grovedb_proof.is_empty() {
        return Err(WillowError::ProofVerificationFailed(
            "GroveDB proof is empty".into(),
        ));
    }

    let empty_path: Vec<Vec<u8>> = vec![];
    let mut query = Query::new();
    query.insert_key(key.to_vec());
    let path_query = PathQuery::new_unsized(empty_path, query);
    let version = GroveVersion::latest();

    let (root_hash, _verified) = GroveDb::verify_query(&resp.grovedb_proof, &path_query, version)
        .map_err(|e| {
        WillowError::ProofVerificationFailed(format!("GroveDB verify_query failed: {}", e))
    })?;

    if root_hash != resp.state_root {
        return Err(WillowError::ProofVerificationFailed(format!(
            "GroveDB proof root {} does not match response state_root {}",
            hex::encode(root_hash),
            hex::encode(resp.state_root),
        )));
    }

    Ok(())
}

fn verify_gkr_proof(proof: &GkrProofData, expected_state_root: [u8; 32]) -> Result<()> {
    if proof.public_inputs.output_root != expected_state_root {
        return Err(WillowError::ProofVerificationFailed(format!(
            "GKR proof output_root {} does not match response state_root {}",
            hex::encode(proof.public_inputs.output_root),
            hex::encode(expected_state_root),
        )));
    }

    if proof.proof.len() >= FULL_HEADER.len() && &proof.proof[..FULL_HEADER.len()] == FULL_HEADER {
        return Err(WillowError::ProofVerificationFailed(
            "Phase 1 SDK verifies GKR_PROOF_BINDING_ONLY only; the indexer \
             returned a GKR_PROOF_FULL proof. Configure the indexer to \
             produce binding-only proofs or wait for the SDK's full-GKR \
             verifier (planned follow-up)."
                .into(),
        ));
    }

    verify_binding_only_proof(
        &proof.proof,
        &proof.public_inputs,
        proof.verification_key_hash,
    )
}

/// Verify a `GKR_PROOF_BINDING_ONLY` proof byte-for-byte against the format
/// produced by `willow-gkr`'s prover. This is intentionally a hand-rolled
/// reimplementation of the binding-only branch in
/// `crates/gkr/src/verifier.rs::verify_binding_proof`: keeping the verifier
/// tiny is the whole point of the SDK side, and the binding-only format
/// only needs SHA-256 — no Expander, no GroveDB, no Arkworks.
///
/// **Soundness caveat.** Binding-only proofs guarantee that the prover knew
/// a witness consistent with the claimed public inputs *and* committed to
/// it via SHA-256. They do not have full GKR cryptographic soundness — a
/// malicious prover with knowledge of the witness layout could in
/// principle construct a "valid" binding-only proof for an incorrect
/// transformation. Use binding-only mode only when the prover is trusted
/// (the Phase 1 hosted-service model in `docs/VERIFIABLE_RPC.md`); for
/// untrusted indexers, use the future full-GKR verifier.
fn verify_binding_only_proof(
    proof: &[u8],
    public_inputs: &GkrPublicInputs,
    verification_key_hash: [u8; 32],
) -> Result<()> {
    const HEADER_LEN: usize = BINDING_HEADER.len(); // 22
    const MIN_LEN: usize = 131; // header + version + circuit_version + pi_hash + meta + commitment

    if proof.len() < MIN_LEN {
        return Err(WillowError::ProofVerificationFailed(format!(
            "binding-only proof too short: {} < {}",
            proof.len(),
            MIN_LEN
        )));
    }

    if &proof[..HEADER_LEN] != BINDING_HEADER {
        return Err(WillowError::ProofVerificationFailed(
            "binding-only proof header mismatch".into(),
        ));
    }

    let format_version = proof[HEADER_LEN];
    if format_version != BINDING_FORMAT_VERSION {
        return Err(WillowError::ProofVerificationFailed(format!(
            "unsupported binding-only proof format version {} (expected {})",
            format_version, BINDING_FORMAT_VERSION
        )));
    }

    let cv_start = HEADER_LEN + 1;
    let proof_circuit_version: [u8; 32] = proof[cv_start..cv_start + 32]
        .try_into()
        .map_err(|_| WillowError::ProofVerificationFailed("circuit_version slice".into()))?;

    if proof_circuit_version != verification_key_hash {
        return Err(WillowError::ProofVerificationFailed(format!(
            "circuit version mismatch: proof carries {} but response says {}",
            hex::encode(&proof_circuit_version[..8]),
            hex::encode(&verification_key_hash[..8])
        )));
    }

    let pi_hash_start = cv_start + 32;
    let proof_pi_hash: [u8; 32] = proof[pi_hash_start..pi_hash_start + 32]
        .try_into()
        .map_err(|_| WillowError::ProofVerificationFailed("public_input_hash slice".into()))?;

    let mut hasher = Sha256::new();
    hasher.update(public_inputs.input_commitment);
    hasher.update(public_inputs.output_root);
    hasher.update(public_inputs.config_hash);
    hasher.update(public_inputs.block_range.0.to_be_bytes());
    hasher.update(public_inputs.block_range.1.to_be_bytes());
    let expected_pi_hash: [u8; 32] = hasher.finalize().into();

    if !ct_eq(&proof_pi_hash, &expected_pi_hash) {
        return Err(WillowError::ProofVerificationFailed(
            "public input hash mismatch — proof does not bind to the response's GkrPublicInputs"
                .into(),
        ));
    }

    let meta_start = pi_hash_start + 32;
    let commitment_start = meta_start + 12; // 3 × u32 metadata
    let commitment: [u8; 32] = proof[commitment_start..commitment_start + 32]
        .try_into()
        .map_err(|_| WillowError::ProofVerificationFailed("witness_commitment slice".into()))?;

    if commitment.iter().all(|&b| b == 0) {
        return Err(WillowError::ProofVerificationFailed(
            "witness commitment is all zero".into(),
        ));
    }

    let mut wc_hasher = Sha256::new();
    wc_hasher.update(&proof[..commitment_start]);
    wc_hasher.update(b"witness_commitment");
    let expected_commitment: [u8; 32] = wc_hasher.finalize().into();

    if !ct_eq(&commitment, &expected_commitment) {
        return Err(WillowError::ProofVerificationFailed(
            "witness commitment recomputation mismatch — proof bytes were tampered with".into(),
        ));
    }

    Ok(())
}

/// Constant-time byte comparison. Avoids leaking proof contents via
/// timing — important for any cryptographic equality check.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::WillowClient;
    use willow_types::consensus::indexing_transactions::{GkrProofData, GkrPublicInputs};

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
            gkr_proof: Some(GkrProofData {
                proof: vec![0xbb; 64],
                public_inputs: GkrPublicInputs {
                    input_commitment: [1; 32],
                    output_root: state_root,
                    block_range: (tip.saturating_sub(100), tip),
                    config_hash: [2; 32],
                },
                verification_key_hash: [3; 32],
                proof_size_bytes: 64,
                generation_time_ms: 1,
                gpu_accelerated: false,
            }),
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

    #[tokio::test]
    async fn verify_gkr_proof_rejects_mismatched_root() {
        let proof = GkrProofData {
            proof: vec![0; 64],
            public_inputs: GkrPublicInputs {
                input_commitment: [0; 32],
                output_root: [7; 32],
                block_range: (0, 10),
                config_hash: [0; 32],
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

    #[tokio::test]
    async fn verify_grovedb_rejects_empty_proof() {
        let mut resp = mk_response([0; 32], 0);
        resp.grovedb_proof.clear();
        let err = verify_grovedb_proof(&resp, &resp.key.clone())
            .expect_err("empty proof must be rejected");
        assert!(err.to_string().contains("empty"));
    }

    /// Build a valid binding-only proof byte sequence matching the format
    /// produced by `crates/gkr/src/prover.rs::generate_binding_only_proof`.
    /// Used to test the SDK's hand-rolled verifier without needing the
    /// Expander stack.
    fn build_binding_only_proof(
        circuit_version: [u8; 32],
        public_inputs: &GkrPublicInputs,
    ) -> Vec<u8> {
        let mut proof = Vec::with_capacity(131);
        proof.extend_from_slice(BINDING_HEADER);
        proof.push(BINDING_FORMAT_VERSION);
        proof.extend_from_slice(&circuit_version);

        let mut hasher = Sha256::new();
        hasher.update(public_inputs.input_commitment);
        hasher.update(public_inputs.output_root);
        hasher.update(public_inputs.config_hash);
        hasher.update(public_inputs.block_range.0.to_be_bytes());
        hasher.update(public_inputs.block_range.1.to_be_bytes());
        let pi_hash: [u8; 32] = hasher.finalize().into();
        proof.extend_from_slice(&pi_hash);

        // Witness metadata: 3 × u32 placeholders.
        proof.extend_from_slice(&1u32.to_be_bytes());
        proof.extend_from_slice(&2u32.to_be_bytes());
        proof.extend_from_slice(&3u32.to_be_bytes());

        let mut wc_hasher = Sha256::new();
        wc_hasher.update(&proof);
        wc_hasher.update(b"witness_commitment");
        let commitment: [u8; 32] = wc_hasher.finalize().into();
        proof.extend_from_slice(&commitment);
        proof
    }

    #[test]
    fn binding_only_verifier_accepts_valid_proof() {
        let pi = GkrPublicInputs {
            input_commitment: [0xaa; 32],
            output_root: [0xbb; 32],
            block_range: (1_000, 2_000),
            config_hash: [0xcc; 32],
        };
        let proof_bytes = build_binding_only_proof([0x55; 32], &pi);
        verify_binding_only_proof(&proof_bytes, &pi, [0x55; 32])
            .expect("freshly built binding-only proof must verify");
    }

    #[test]
    fn binding_only_verifier_rejects_tampered_pi_hash() {
        let pi = GkrPublicInputs {
            input_commitment: [0xaa; 32],
            output_root: [0xbb; 32],
            block_range: (1, 2),
            config_hash: [0xcc; 32],
        };
        let proof_bytes = build_binding_only_proof([0x55; 32], &pi);

        // Pretend the prover lied about output_root — the recomputed
        // SHA-256 will diverge from what the proof carries.
        let lying_pi = GkrPublicInputs {
            output_root: [0xff; 32],
            ..pi.clone()
        };
        let err = verify_binding_only_proof(&proof_bytes, &lying_pi, [0x55; 32])
            .expect_err("tampered public inputs must be rejected");
        assert!(err.to_string().contains("public input hash mismatch"));
    }

    #[test]
    fn binding_only_verifier_rejects_circuit_version_mismatch() {
        let pi = GkrPublicInputs {
            input_commitment: [1; 32],
            output_root: [2; 32],
            block_range: (0, 1),
            config_hash: [3; 32],
        };
        let proof = build_binding_only_proof([0x55; 32], &pi);
        let err = verify_binding_only_proof(&proof, &pi, [0x66; 32])
            .expect_err("circuit version mismatch must be rejected");
        assert!(err.to_string().contains("circuit version mismatch"));
    }

    #[test]
    fn binding_only_verifier_rejects_full_gkr_format() {
        let pi = GkrPublicInputs {
            input_commitment: [1; 32],
            output_root: [2; 32],
            block_range: (0, 1),
            config_hash: [3; 32],
        };
        // Pretend a GKR_PROOF_FULL came down the wire — must be cleanly
        // rejected with a precise error rather than a format-check stutter.
        let mut full_proof = FULL_HEADER.to_vec();
        full_proof.extend_from_slice(&[0u8; 200]);

        let proof_data = GkrProofData {
            proof: full_proof,
            public_inputs: pi.clone(),
            verification_key_hash: [0x55; 32],
            proof_size_bytes: 0,
            generation_time_ms: 0,
            gpu_accelerated: false,
        };
        let err = verify_gkr_proof(&proof_data, pi.output_root)
            .expect_err("full proof must be rejected by phase-1 verifier");
        assert!(err.to_string().contains("Phase 1"));
        assert!(err.to_string().contains("GKR_PROOF_FULL"));
    }

    /// Wire-format compat: the JSON the indexer emits decodes into our
    /// `VerifiableRpcResponse` cleanly, then the binding-only verifier
    /// accepts the embedded proof. This is the cross-crate guarantee the
    /// rest of the test suite mocks around — keep it locked here.
    #[test]
    fn json_wire_compat_then_binding_only_verifies() {
        let pi = GkrPublicInputs {
            input_commitment: [0x42; 32],
            output_root: [0x99; 32],
            block_range: (10, 20),
            config_hash: [0x77; 32],
        };
        let proof = build_binding_only_proof([0x55; 32], &pi);
        let response = VerifiableRpcResponse {
            subgrove_id: "sg".into(),
            key: vec![1, 2, 3],
            answer: vec![4, 5, 6, 7],
            answer_exists: true,
            checkpoint_id: [0x88; 32],
            state_root: pi.output_root,
            block_range: pi.block_range,
            grovedb_proof: vec![0xab, 0xcd], // placeholder; not verified here
            gkr_proof: Some(GkrProofData {
                proof_size_bytes: proof.len() as u64,
                proof,
                public_inputs: pi.clone(),
                verification_key_hash: [0x55; 32],
                generation_time_ms: 7,
                gpu_accelerated: false,
            }),
            served_at_unix_secs: 1_700_000_000,
        };

        // Round-trip through JSON (the actual transport).
        let json = serde_json::to_string(&response).expect("encode");
        let decoded: VerifiableRpcResponse = serde_json::from_str(&json).expect("decode");

        // Binding-only verification accepts the embedded proof.
        verify_gkr_proof(decoded.gkr_proof.as_ref().unwrap(), decoded.state_root)
            .expect("verifier accepts");
    }

    #[test]
    fn binding_only_verifier_rejects_short_proof() {
        let pi = GkrPublicInputs {
            input_commitment: [0; 32],
            output_root: [0; 32],
            block_range: (0, 0),
            config_hash: [0; 32],
        };
        let err = verify_binding_only_proof(&vec![0u8; 50], &pi, [0; 32])
            .expect_err("short proof must be rejected");
        assert!(err.to_string().contains("too short"));
    }
}
