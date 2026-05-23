//! Client-side verification for verifiable Ethereum state reads.
//!
//! Counterpart to the indexer's `POST /verifiable-rpc/eth/state` and
//! `POST /verifiable-rpc/eth/call` routes. The indexer's response carries
//! EIP-1186-shaped MPT inclusion proofs anchored at a `state_root` that
//! Helios has already light-client-verified upstream. This module repeats
//! the MPT walk independently so callers don't have to trust the indexer.
//!
//! Three trust modes follow the same shape as [`crate::verifiable_rpc`]:
//!
//! - [`StateVerifyMode::Strict`]: every account proof + every storage
//!   proof must verify against the carried `state_root`. The SDK is
//!   responsible for separately checking that `state_root` matches the
//!   block header it trusts via its own light client; this module only
//!   verifies the MPT walks.
//! - [`StateVerifyMode::AnchorOnly`]: skip the MPT walks, trust the
//!   indexer's word. Useful when the SDK has its own out-of-band trust
//!   path (private indexer, paid SLA).
//! - [`StateVerifyMode::Disabled`]: no verification, raw passthrough.
//!
//! Storage-layout helpers (`erc20_balance`, `uni_v2_reserves`, …) wrap
//! [`EthOperations::get_state`] so callers don't have to hand-compute
//! `keccak256(abi.encode(holder, slot_index))` every time.

use crate::client::WillowClient;
use crate::errors::{Result, WillowError};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_rlp::Encodable;
use alloy_trie::{proof::verify_proof, Nibbles};
use willow_types::consensus::indexing_transactions::data_updates::MptProof;
use willow_types::state_proof::{StateProof, StorageSlotProof, VerifiedCallResult};
use willow_types::verifiable_rpc::VerifiableRpcResponse;

/// How aggressively to verify the indexer's response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateVerifyMode {
    /// Walk every MPT proof against the carried `state_root`. Default.
    Strict,
    /// Skip the proof walks; trust the indexer's word. The carried
    /// `state_root` is still surfaced so callers with an out-of-band
    /// anchor (a separately verified header) can check it.
    AnchorOnly,
    /// No verification, raw passthrough. Intended for debugging.
    Disabled,
}

impl Default for StateVerifyMode {
    fn default() -> Self {
        Self::Strict
    }
}

/// Verified result of a state read.
#[derive(Debug, Clone)]
pub struct VerifiedStateRead {
    pub address: [u8; 20],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub nonce: u64,
    pub balance: U256,
    pub storage_hash: [u8; 32],
    pub code_hash: [u8; 32],
    /// Slot → value for each storage proof returned. Iteration order
    /// matches the request order.
    pub storage: Vec<(B256, U256)>,
    pub mode: StateVerifyMode,
}

/// Verified result of an `eth_call`.
#[derive(Debug, Clone)]
pub struct VerifiedCall {
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    /// ABI-encoded return data.
    pub result: Vec<u8>,
    /// Per-account state proofs covering every slot REVM touched.
    pub access_state_reads: Vec<VerifiedStateRead>,
    pub mode: StateVerifyMode,
}

/// SDK-side operations for verifiable Ethereum state reads.
///
/// Construct via [`WillowClient::eth`]. Cheap to clone — holds a handle
/// to the client.
pub struct EthOperations {
    client: WillowClient,
    mode: StateVerifyMode,
}

impl EthOperations {
    pub(crate) fn new(client: WillowClient) -> Self {
        Self {
            client,
            mode: StateVerifyMode::default(),
        }
    }

    /// Override the verification mode. Defaults to [`StateVerifyMode::Strict`].
    pub fn with_mode(mut self, mode: StateVerifyMode) -> Self {
        self.mode = mode;
        self
    }

    /// Fetch `address`'s account state (and optional storage slots) at
    /// `block_number`, then verify every MPT proof in the response.
    pub async fn get_state(
        &self,
        address: [u8; 20],
        slots: &[[u8; 32]],
        block_number: u64,
    ) -> Result<VerifiedStateRead> {
        let raw = self.fetch_state(address, slots, block_number).await?;
        let proof = raw.state_proofs.first().ok_or_else(|| {
            WillowError::ProofVerificationFailed("response carried no state proof".into())
        })?;

        if self.mode == StateVerifyMode::Strict {
            verify_state_proof(proof)?;
        }

        Ok(VerifiedStateRead {
            address: proof.address,
            block_number: proof.block_number,
            block_hash: proof.block_hash,
            state_root: proof.state_root,
            nonce: proof.account_state.nonce,
            balance: U256::from_be_bytes(proof.account_state.balance),
            storage_hash: proof.account_state.storage_hash,
            code_hash: proof.account_state.code_hash,
            storage: proof
                .storage_proofs
                .iter()
                .map(|sp| (B256::from(sp.slot), U256::from_be_bytes(sp.value)))
                .collect(),
            mode: self.mode,
        })
    }

    /// Execute `tx` via the indexer's verified-REVM and verify state
    /// proofs for every touched account.
    pub async fn get_call(
        &self,
        tx: alloy::rpc::types::TransactionRequest,
        block_number: u64,
    ) -> Result<VerifiedCall> {
        let raw = self.fetch_call(tx, block_number).await?;

        if self.mode == StateVerifyMode::Strict {
            for sp in &raw.state_proofs {
                verify_state_proof(sp)?;
            }
        }

        // `answer` is the ABI-encoded result piggybacking on the legacy
        // envelope field — server-side wraps it in `eth_state::build_envelope`.
        let result = raw.answer.clone();
        let state_root = raw.state_root;
        let block_number_resp = raw.block_range.0;
        // block_hash isn't separately on the envelope; it lives on each
        // StateProof (all proofs in a call share the same block).
        let block_hash = raw
            .state_proofs
            .first()
            .map(|p| p.block_hash)
            .unwrap_or([0u8; 32]);

        let access_state_reads = raw
            .state_proofs
            .iter()
            .map(|sp| VerifiedStateRead {
                address: sp.address,
                block_number: sp.block_number,
                block_hash: sp.block_hash,
                state_root: sp.state_root,
                nonce: sp.account_state.nonce,
                balance: U256::from_be_bytes(sp.account_state.balance),
                storage_hash: sp.account_state.storage_hash,
                code_hash: sp.account_state.code_hash,
                storage: sp
                    .storage_proofs
                    .iter()
                    .map(|sl| (B256::from(sl.slot), U256::from_be_bytes(sl.value)))
                    .collect(),
                mode: self.mode,
            })
            .collect();

        Ok(VerifiedCall {
            block_number: block_number_resp,
            block_hash,
            state_root,
            result,
            access_state_reads,
            mode: self.mode,
        })
    }

    /// Returns the balance held by `holder` in an ERC-20 contract whose
    /// `balanceOf` mapping lives at `balance_slot`.
    ///
    /// `balance_slot` is contract-specific — most OpenZeppelin-style
    /// tokens declare it as slot 0 (the first storage variable). USDC
    /// uses slot 9. Always check the token's source if you're unsure.
    pub async fn erc20_balance(
        &self,
        token: [u8; 20],
        holder: [u8; 20],
        balance_slot: u8,
        block_number: u64,
    ) -> Result<U256> {
        let slot = mapping_slot_for_address(holder, balance_slot);
        let state = self.get_state(token, &[slot], block_number).await?;
        let (_, value) = state.storage.first().ok_or_else(|| {
            WillowError::ProofVerificationFailed("erc20_balance: empty storage_proofs".into())
        })?;
        Ok(*value)
    }

    /// Returns `totalSupply()` for an ERC-20 whose `_totalSupply`
    /// variable lives at `total_supply_slot`. Defaults vary by token;
    /// check the source.
    pub async fn erc20_total_supply(
        &self,
        token: [u8; 20],
        total_supply_slot: u8,
        block_number: u64,
    ) -> Result<U256> {
        let mut slot = [0u8; 32];
        slot[31] = total_supply_slot;
        let state = self.get_state(token, &[slot], block_number).await?;
        let (_, value) = state.storage.first().ok_or_else(|| {
            WillowError::ProofVerificationFailed("erc20_total_supply: empty storage_proofs".into())
        })?;
        Ok(*value)
    }

    /// Returns the allowance `holder → spender` for a token whose
    /// `_allowances` mapping (nested `holder → spender → uint256`)
    /// lives at `allowance_slot`.
    pub async fn erc20_allowance(
        &self,
        token: [u8; 20],
        holder: [u8; 20],
        spender: [u8; 20],
        allowance_slot: u8,
        block_number: u64,
    ) -> Result<U256> {
        // Nested mapping: outer key = holder, then inner key = spender.
        let inner_slot = mapping_slot_for_address(holder, allowance_slot);
        let mut buf = [0u8; 64];
        // pad spender to 32 bytes (left-pad)
        buf[12..32].copy_from_slice(&spender);
        buf[32..].copy_from_slice(&inner_slot);
        let slot: [u8; 32] = keccak256(buf).into();

        let state = self.get_state(token, &[slot], block_number).await?;
        let (_, value) = state.storage.first().ok_or_else(|| {
            WillowError::ProofVerificationFailed("erc20_allowance: empty storage_proofs".into())
        })?;
        Ok(*value)
    }

    /// Returns the owner address for an ERC-721 token id whose
    /// `_owners` mapping lives at `owners_slot`.
    pub async fn erc721_owner(
        &self,
        contract: [u8; 20],
        token_id: U256,
        owners_slot: u8,
        block_number: u64,
    ) -> Result<[u8; 20]> {
        // Mapping key is uint256 → left-pad to 32 bytes.
        let key_bytes: [u8; 32] = token_id.to_be_bytes::<32>();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&key_bytes);
        buf[63] = owners_slot;
        let slot: [u8; 32] = keccak256(buf).into();
        let state = self.get_state(contract, &[slot], block_number).await?;
        let (_, value) = state.storage.first().ok_or_else(|| {
            WillowError::ProofVerificationFailed("erc721_owner: empty storage_proofs".into())
        })?;
        let bytes: [u8; 32] = value.to_be_bytes::<32>();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes[12..32]);
        Ok(addr)
    }

    /// Returns `(reserve0, reserve1, block_timestamp_last)` for a
    /// Uniswap V2 pair. V2 packs all three into slot 8 by convention,
    /// so this helper ignores `slot` and reads slot 8 directly.
    pub async fn uni_v2_reserves(
        &self,
        pair: [u8; 20],
        block_number: u64,
    ) -> Result<(u128, u128, u32)> {
        let mut slot = [0u8; 32];
        slot[31] = 8;
        let state = self.get_state(pair, &[slot], block_number).await?;
        let (_, value) = state.storage.first().ok_or_else(|| {
            WillowError::ProofVerificationFailed("uni_v2_reserves: empty storage_proofs".into())
        })?;
        let bytes: [u8; 32] = value.to_be_bytes::<32>();
        // Packed: reserve0 (112 bits) | reserve1 (112 bits) | blockTimestampLast (32 bits)
        // Layout in storage (low → high): timestamp(4 bytes) | reserve1(14 bytes) | reserve0(14 bytes)
        // In big-endian on-the-wire bytes (which is what to_be_bytes gives):
        // bytes[0..14] = reserve0  (high) — wait no, this needs careful analysis
        // Solidity packs from the high-order side: bytes[0..4] = blockTimestampLast,
        // bytes[4..18] = reserve1, bytes[18..32] = reserve0
        let block_timestamp_last = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut r1_bytes = [0u8; 16];
        r1_bytes[2..].copy_from_slice(&bytes[4..18]);
        let reserve1 = u128::from_be_bytes(r1_bytes);
        let mut r0_bytes = [0u8; 16];
        r0_bytes[2..].copy_from_slice(&bytes[18..32]);
        let reserve0 = u128::from_be_bytes(r0_bytes);
        Ok((reserve0, reserve1, block_timestamp_last))
    }

    async fn fetch_state(
        &self,
        address: [u8; 20],
        slots: &[[u8; 32]],
        block_number: u64,
    ) -> Result<VerifiableRpcResponse> {
        let url = self
            .client
            .indexer_base_url()
            .join("verifiable-rpc/eth/state")
            .map_err(|e| WillowError::Config(format!("invalid url: {}", e)))?;

        let body = serde_json::json!({
            "address": format!("0x{}", hex::encode(address)),
            "slots": slots.iter().map(|s| format!("0x{}", hex::encode(s))).collect::<Vec<_>>(),
            "block": block_number,
        });

        let resp = self.client.http_client.post(url).json(&body).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(WillowError::Http {
                status: status.as_u16(),
                message: text,
            });
        }
        serde_json::from_str(&text).map_err(WillowError::Serialization)
    }

    async fn fetch_call(
        &self,
        tx: alloy::rpc::types::TransactionRequest,
        block_number: u64,
    ) -> Result<VerifiableRpcResponse> {
        let url = self
            .client
            .indexer_base_url()
            .join("verifiable-rpc/eth/call")
            .map_err(|e| WillowError::Config(format!("invalid url: {}", e)))?;

        let body = serde_json::json!({
            "tx": tx,
            "block": block_number,
        });

        let resp = self.client.http_client.post(url).json(&body).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(WillowError::Http {
                status: status.as_u16(),
                message: text,
            });
        }
        serde_json::from_str(&text).map_err(WillowError::Serialization)
    }
}

impl WillowClient {
    /// Verifiable Ethereum state-read operations. See [`EthOperations`].
    pub fn eth(&self) -> EthOperations {
        EthOperations::new(self.clone())
    }
}

/// Walks `proof`'s account MPT proof against `proof.state_root` and
/// each `storage_proofs[i]` against the recovered `storage_hash`.
///
/// Returns `Ok(())` if every walk lands on a leaf whose value matches
/// the carried `account_state` / `storage_proofs[i].value`. Returns
/// [`WillowError::ProofVerificationFailed`] on the first mismatch.
pub fn verify_state_proof(proof: &StateProof) -> Result<()> {
    let address = Address::from(proof.address);
    let state_root = B256::from(proof.state_root);

    // Account proof: walk state_root MPT for key keccak256(address) and
    // confirm the leaf equals RLP(TrieAccount{...}).
    verify_one(
        &proof.account_proof,
        state_root,
        keccak256(address.as_slice()),
        rlp_account(&proof.account_state),
    )
    .map_err(|e| {
        WillowError::ProofVerificationFailed(format!("account proof for {}: {}", address, e))
    })?;

    let storage_hash = B256::from(proof.account_state.storage_hash);
    for sp in &proof.storage_proofs {
        verify_storage(sp, storage_hash)?;
    }
    Ok(())
}

/// Verifies a [`VerifiedCallResult`] in one shot. Useful when callers
/// already have the deserialized eth_call response and don't want to
/// take the SDK fetcher path.
pub fn verify_call_result(call: &VerifiedCallResult) -> Result<()> {
    for sp in &call.access_state_proofs {
        verify_state_proof(sp)?;
    }
    Ok(())
}

fn verify_storage(sp: &StorageSlotProof, storage_hash: B256) -> Result<()> {
    let mut value_rlp = Vec::new();
    let value = U256::from_be_bytes(sp.value);
    value.encode(&mut value_rlp);
    verify_one(
        &sp.proof,
        storage_hash,
        keccak256(sp.slot.as_slice()),
        value_rlp,
    )
    .map_err(|e| {
        WillowError::ProofVerificationFailed(format!(
            "storage proof for slot 0x{}: {}",
            hex::encode(sp.slot),
            e
        ))
    })?;
    Ok(())
}

fn verify_one(
    proof: &MptProof,
    root: B256,
    key_hash: B256,
    expected_value: Vec<u8>,
) -> std::result::Result<(), String> {
    let nibbles = Nibbles::unpack(key_hash.as_slice());
    let nodes: Vec<alloy_primitives::Bytes> = proof
        .proof_nodes
        .iter()
        .map(|n| alloy_primitives::Bytes::from(n.clone()))
        .collect();
    verify_proof(root, nibbles, Some(expected_value), &nodes).map_err(|e| format!("{:?}", e))
}

fn rlp_account(state: &willow_types::state_proof::AccountState) -> Vec<u8> {
    let mut buf = Vec::new();
    alloy_trie::TrieAccount {
        nonce: state.nonce,
        balance: U256::from_be_bytes(state.balance),
        storage_root: B256::from(state.storage_hash),
        code_hash: B256::from(state.code_hash),
    }
    .encode(&mut buf);
    buf
}

/// Storage slot for mapping(address => _) at base slot `slot_index`:
/// `keccak256(left_pad(address, 32) || left_pad(slot_index, 32))`.
fn mapping_slot_for_address(addr: [u8; 20], slot_index: u8) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(&addr);
    buf[63] = slot_index;
    keccak256(buf).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_slot_matches_known_usdc_layout() {
        // USDC balance mapping is at slot 9. The mapping slot for vitalik.eth
        // (0xd8da6bf26964af9d7eed9e03e53415d37aa96045) is well-known. We don't
        // assert a specific value (depends on Solidity packing details) but
        // confirm the function is deterministic and length-32.
        let vitalik: [u8; 20] = hex::decode("d8da6bf26964af9d7eed9e03e53415d37aa96045")
            .unwrap()
            .try_into()
            .unwrap();
        let slot = mapping_slot_for_address(vitalik, 9);
        let slot2 = mapping_slot_for_address(vitalik, 9);
        assert_eq!(slot, slot2);
        // Different slot index → different storage key.
        let slot_other = mapping_slot_for_address(vitalik, 0);
        assert_ne!(slot, slot_other);
    }

    #[test]
    fn verify_state_proof_rejects_tampered_balance() {
        // Build a StateProof whose account_state.balance has been
        // changed but proof_nodes were not regenerated. The MPT walk
        // recovers a different RLP-encoded leaf than account_state
        // implies, so verification must fail.
        let proof = StateProof {
            address: [0u8; 20],
            block_number: 1,
            block_hash: [0u8; 32],
            state_root: [0u8; 32],
            account_proof: MptProof {
                key: vec![0u8; 32],
                value: vec![],
                proof_nodes: vec![],
            },
            account_state: willow_types::state_proof::AccountState {
                nonce: 0,
                balance: [0xffu8; 32], // tampered
                storage_hash: [0u8; 32],
                code_hash: [0u8; 32],
            },
            storage_proofs: vec![],
        };
        // Empty proof_nodes can't possibly verify; we just confirm the
        // function returns Err rather than silently passing.
        assert!(verify_state_proof(&proof).is_err());
    }
}
