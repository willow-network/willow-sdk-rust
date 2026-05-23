//! Client-side verifiable RPC: query an indexer and verify locally.
//!
//! This module is the SDK counterpart to the `GET /verifiable-rpc/:subgrove/:key`
//! endpoint implemented by `willow-indexer-node`. On each response we run the
//! two proofs side by side:
//!
//!  1. **GKR proof** (if present) — confirms the indexer's claimed
//!     `state_root` is the correct output of transforming committed events.
//!     Always supports `GKR_PROOF_BINDING_ONLY` (pure SHA-256, no heavy
//!     deps). With the `verifiable-rpc-full` cargo feature enabled, also
//!     verifies `GKR_PROOF_FULL` — the SDK embeds the compiled circuit
//!     bytes at build time via `willow_gkr_verify::circuits` and runs
//!     the real cryptographic verifier via the `full` feature on the
//!     thin crate.
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
use std::time::{SystemTime, UNIX_EPOCH};
use willow_gkr_verify::{
    detect_format, verify_binding_only_proof as verify_binding_only, ProofFormat,
};
use willow_types::consensus::indexing_transactions::GkrProofData;
use willow_types::verifiable_rpc::VerifiableRpcResponse;

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

/// Verify the GKR proof carried in a verifiable-RPC response.
///
/// Cross-checks the proof's claimed `output_root` against the response's
/// `state_root`, then routes to `willow-gkr-verify` by format:
///
///  - `GKR_PROOF_BINDING_ONLY` → pure-sha2 binding check (always
///    available).
///  - `GKR_PROOF_FULL` → full GKR verification via the `full` feature.
///    Needs the serialized circuit bytes for the proof's circuit
///    version; those are embedded at compile time (see
///    `willow_gkr_verify::circuits`). Without the feature, surfaces a
///    precise "not compiled in" error.
fn verify_gkr_proof(proof: &GkrProofData, expected_state_root: [u8; 32]) -> Result<()> {
    if proof.public_inputs.output_root != expected_state_root {
        return Err(WillowError::ProofVerificationFailed(format!(
            "GKR proof output_root {} does not match response state_root {}",
            hex::encode(proof.public_inputs.output_root),
            hex::encode(expected_state_root),
        )));
    }

    match detect_format(&proof.proof) {
        ProofFormat::BindingOnly => verify_binding_only(
            &proof.proof,
            &proof.public_inputs,
            proof.verification_key_hash,
        )
        .map_err(|e| WillowError::ProofVerificationFailed(e.to_string())),
        ProofFormat::Full => verify_full(proof),
        ProofFormat::Unknown => Err(WillowError::ProofVerificationFailed(
            "GKR proof header is not a recognised format".into(),
        )),
    }
}

/// Full-GKR verification dispatch.
///
/// Routing precedence (first matching cfg wins):
///
///  1. `verifiable-rpc-pure` — pure-Rust verifier
///     (`willow-gkr-verify-pure`), no Expander in the dep graph,
///     compiles to `wasm32-unknown-unknown`. Same cryptographic
///     guarantees as the native path; cross-validated byte-for-byte
///     against Expander via fixtures.
///  2. `verifiable-rpc-full` — native Expander verifier via
///     `willow-gkr-verify::full`. Fastest on desktops/servers;
///     drags in several MB of C-FFI dependencies.
///  3. Neither → return a precise "not compiled in" error.
#[cfg(feature = "verifiable-rpc-pure")]
fn verify_full(proof: &GkrProofData) -> Result<()> {
    willow_gkr_verify_pure::verify_full_proof_with_registry(
        &proof.proof,
        &proof.public_inputs,
        proof.verification_key_hash,
    )
    .map_err(|e| WillowError::ProofVerificationFailed(e.to_string()))
}

#[cfg(all(feature = "verifiable-rpc-full", not(feature = "verifiable-rpc-pure")))]
fn verify_full(proof: &GkrProofData) -> Result<()> {
    let circuit_bytes = willow_gkr_verify::get_circuit_bytes(&proof.verification_key_hash)
        .ok_or_else(|| {
            WillowError::ProofVerificationFailed(format!(
                "no embedded circuit for verification_key_hash {}; SDK cannot \
                 verify full GKR proofs for this circuit — rebuild the SDK \
                 with an updated willow-gkr-verify after re-exporting",
                hex::encode(&proof.verification_key_hash[..8])
            ))
        })?;

    willow_gkr_verify::verify_full_proof(
        circuit_bytes,
        &proof.proof,
        &proof.public_inputs,
        proof.verification_key_hash,
    )
    .map_err(|e| WillowError::ProofVerificationFailed(e.to_string()))
}

#[cfg(not(any(feature = "verifiable-rpc-full", feature = "verifiable-rpc-pure")))]
fn verify_full(_proof: &GkrProofData) -> Result<()> {
    Err(WillowError::ProofVerificationFailed(
        "indexer returned a GKR_PROOF_FULL proof; enable the \
         `verifiable-rpc-full` (native) or `verifiable-rpc-pure` \
         (wasm-friendly) cargo feature on the SDK to verify it, \
         or use VerifyMode::GroveDbOnly and anchor state_root via \
         consensus. See docs/todo/proposal-pure-rust-verifier.md."
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::WillowClient;
    use sha2::{Digest, Sha256};
    use willow_gkr_verify::{BINDING_FORMAT_VERSION, BINDING_HEADER, FULL_HEADER};
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

    /// Build a binding-only proof in the byte-exact format produced by
    /// `willow_gkr::prover::GkrProver::generate_binding_only_proof`. The
    /// verifier crate itself covers the full format-check matrix; here we
    /// only need to fabricate one valid proof for the SDK dispatch tests.
    fn build_valid_binding_only(pi: &GkrPublicInputs, circuit_version: [u8; 32]) -> Vec<u8> {
        let mut proof = Vec::with_capacity(131);
        proof.extend_from_slice(BINDING_HEADER);
        proof.push(BINDING_FORMAT_VERSION);
        proof.extend_from_slice(&circuit_version);
        proof.extend_from_slice(&willow_gkr_verify::binding_only::compute_public_input_hash(
            pi,
        ));
        proof.extend_from_slice(&1u32.to_be_bytes());
        proof.extend_from_slice(&2u32.to_be_bytes());
        proof.extend_from_slice(&3u32.to_be_bytes());
        let mut hasher = Sha256::new();
        hasher.update(&proof);
        hasher.update(b"witness_commitment");
        let commitment: [u8; 32] = hasher.finalize().into();
        proof.extend_from_slice(&commitment);
        proof
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

    /// Without the `verifiable-rpc-full` feature, full proofs are
    /// surfaced with a precise "not compiled in" error so callers can
    /// decide what to do (drop to GroveDbOnly, recompile, etc.).
    #[cfg(not(feature = "verifiable-rpc-full"))]
    #[test]
    fn verify_gkr_proof_rejects_full_format_without_feature() {
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
            verification_key_hash: [0x55; 32],
            proof_size_bytes: 0,
            generation_time_ms: 0,
            gpu_accelerated: false,
        };
        let err = verify_gkr_proof(&data, pi.output_root)
            .expect_err("full proof must be rejected when the full feature is off");
        assert!(err.to_string().contains("GKR_PROOF_FULL"));
        assert!(err.to_string().contains("verifiable-rpc-full"));
    }

    /// With the full feature on, a full proof with the wrong
    /// circuit-version hash has no embedded bytes and surfaces a
    /// "no embedded circuit" error. With a matching hash but garbage
    /// payload it fails deserialization or cryptographic verification,
    /// surfacing one of the upstream errors.
    #[cfg(feature = "verifiable-rpc-full")]
    #[test]
    fn verify_gkr_proof_full_feature_rejects_unknown_circuit() {
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
            err.to_string().contains("no embedded circuit"),
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
        assert!(err.to_string().contains("not a recognised format"));
    }

    #[test]
    fn verify_grovedb_rejects_empty_proof() {
        let mut resp = mk_response([0; 32], 0);
        resp.grovedb_proof.clear();
        let err = verify_grovedb_proof(&resp, &resp.key.clone())
            .expect_err("empty proof must be rejected");
        assert!(err.to_string().contains("empty"));
    }

    /// Cross-crate wire-format lock: JSON round-trips through
    /// `VerifiableRpcResponse` and the embedded binding-only proof
    /// verifies via the shared crate's verifier. If this test breaks, the
    /// indexer and SDK have diverged on the on-the-wire format.
    #[test]
    fn json_wire_compat_then_binding_only_verifies() {
        let pi = GkrPublicInputs {
            output_root: [0x99; 32],
            block_range: (10, 20),
            config_hash: [0x77; 32],
            starting_state_root: [0; 32],
        };
        let cv = [0x55; 32];
        let proof = build_valid_binding_only(&pi, cv);
        let response = VerifiableRpcResponse {
            subgrove_id: "sg".into(),
            key: vec![1, 2, 3],
            answer: vec![4, 5, 6, 7],
            answer_exists: true,
            checkpoint_id: [0x88; 32],
            state_root: pi.output_root,
            block_range: pi.block_range,
            grovedb_proof: vec![0xab, 0xcd], // placeholder; not verified here
            gkr_proofs: vec![GkrProofData {
                proof_version: CURRENT_PROOF_VERSION,
                proof_size_bytes: proof.len() as u64,
                proof,
                public_inputs: pi.clone(),
                verification_key_hash: cv,
                generation_time_ms: 7,
                gpu_accelerated: false,
            }],
            completeness_proof: None,
            state_proofs: Vec::new(),
            served_at_unix_secs: 1_700_000_000,
        };

        let json = serde_json::to_string(&response).expect("encode");
        let decoded: VerifiableRpcResponse = serde_json::from_str(&json).expect("decode");
        verify_gkr_proof(&decoded.gkr_proofs[0], decoded.state_root)
            .expect("shared verifier accepts round-tripped proof");
    }
}
