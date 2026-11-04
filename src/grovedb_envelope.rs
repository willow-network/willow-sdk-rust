//! Proof-envelope checks that GroveDB 3.1.0's `verify_query` does not make.
//!
//! GroveDB's layered verifier finds each lower layer by the proof envelope's
//! `lower_layers` map KEY, which is not hash-bound. A server that renames or
//! drops the entry for a subtree on the query path lands in the verifier's
//! empty `else`: the subtree's results vanish with no error and the root hash
//! still verifies. A proof of "K = V" becomes an accepted proof of "K is
//! absent". Once a layer IS present the verifier binds its root to the parent
//! by hash, so requiring descent through every segment of the query path
//! closes the gap. `prove_options` is server-chosen bytes that steer limit
//! accounting, so it is pinned to the default the chain's prover uses.
//!
//! Every `GroveDb::verify_query` call in this SDK runs [`check_envelope`]
//! first, with the same path it verifies against.
//!
//! grovedb-merk 3.1.0 also leaves two gaps inside a layer, which
//! [`check_layers`] and [`verify_item_at_path`] close:
//!
//! - An opaque `Hash` node's hash is taken as given, children or not, so a
//!   forged subtree attached under one still hashes to the real root while
//!   its nodes are read as query results. Opaque proof nodes must stay
//!   childless.
//! - A `KVValueHash` node's value is not hashed: only its value hash enters
//!   the root, so its bytes are bound to nothing. An item is bound only when
//!   proven as a `KV` node, whose value enters the root (the form grovedb's
//!   prover gives every item).

use crate::errors::{Result, WillowError};
use grovedb::operations::proof::{GroveDBProof, LayerProof, ProveOptions};
use grovedb::{Element, GroveDb, PathQuery, Query};
use grovedb_merk::proofs::{Decoder, Node, Op};

/// Reject a proof envelope that does not descend `path`, carries layers below
/// it, or sets non-default prove options.
pub fn check_envelope(proof: &[u8], path: &[Vec<u8>]) -> Result<()> {
    let fail = |m: String| WillowError::ProofVerificationFailed(format!("GroveDB envelope: {m}"));
    let GroveDBProof::V0(v0) = decode_envelope(proof)?;
    if v0.prove_options.decrease_limit_on_empty_sub_query_result
        != ProveOptions::default().decrease_limit_on_empty_sub_query_result
    {
        return Err(fail("non-default prove_options".into()));
    }
    let mut layer: &LayerProof = &v0.root_layer;
    for (depth, seg) in path.iter().enumerate() {
        layer = layer.lower_layers.get(seg).ok_or_else(|| {
            fail(format!(
                "no lower layer for path segment {depth} ({}); the proof does not descend to the query path",
                String::from_utf8_lossy(seg)
            ))
        })?;
    }
    if !layer.lower_layers.is_empty() {
        return Err(fail("unexpected lower layers below the query path".into()));
    }
    Ok(())
}

/// The path a proof descends: from the root layer, the key of each layer's one lower layer,
/// until a layer has none. A layer with more than one lower layer is refused.
pub fn descended_path(proof: &[u8]) -> Result<Vec<Vec<u8>>> {
    let GroveDBProof::V0(v0) = decode_envelope(proof)?;
    let mut path = vec![];
    let mut layer = &v0.root_layer;
    while let Some((key, lower)) = layer.lower_layers.iter().next() {
        if layer.lower_layers.len() > 1 {
            return Err(WillowError::ProofVerificationFailed(
                "GroveDB envelope: a layer with more than one lower layer".into(),
            ));
        }
        path.push(key.clone());
        layer = lower;
    }
    Ok(path)
}

/// The proof envelope, refusing trailing bytes.
fn decode_envelope(proof: &[u8]) -> Result<GroveDBProof> {
    let fail = |m: String| WillowError::ProofVerificationFailed(format!("GroveDB envelope: {m}"));
    let config = bincode2::config::standard()
        .with_big_endian()
        .with_no_limit();
    let (envelope, used): (GroveDBProof, usize) =
        bincode2::decode_from_slice(proof, config).map_err(|e| fail(e.to_string()))?;
    if used != proof.len() {
        return Err(fail(format!("{} trailing bytes", proof.len() - used)));
    }
    Ok(envelope)
}

/// One layer's merk ops, refusing bytes that don't decode.
fn layer_ops(layer: &LayerProof) -> Result<Vec<Op>> {
    Decoder::new(&layer.merk_proof)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| WillowError::ProofVerificationFailed(format!("GroveDB layer: {e}")))
}

/// Refuse a layer whose ops attach a child to an opaque `Hash` node, or don't build one tree.
fn check_ops(ops: &[Op]) -> Result<()> {
    let fail = |m: &str| {
        Err(WillowError::ProofVerificationFailed(format!(
            "GroveDB layer: {m}"
        )))
    };
    // Each stack entry: whether the node at the top of that subtree is an opaque Hash.
    let mut stack: Vec<bool> = Vec::new();
    for op in ops {
        match op {
            Op::Push(node) | Op::PushInverted(node) => stack.push(matches!(node, Node::Hash(_))),
            // Parent ops pop the parent first; Child ops pop the child first.
            Op::Parent | Op::ParentInverted => {
                let (Some(parent), Some(_child)) = (stack.pop(), stack.pop()) else {
                    return fail("a Parent op with fewer than two nodes");
                };
                if parent {
                    return fail("a child attached to an opaque Hash node");
                }
                stack.push(parent);
            }
            Op::Child | Op::ChildInverted => {
                let (Some(_child), Some(parent)) = (stack.pop(), stack.pop()) else {
                    return fail("a Child op with fewer than two nodes");
                };
                if parent {
                    return fail("a child attached to an opaque Hash node");
                }
                stack.push(parent);
            }
        }
    }
    if stack.len() != 1 {
        return fail("the ops don't build exactly one tree");
    }
    Ok(())
}

/// Refuse a proof any of whose layers attaches a child to an opaque `Hash` node (which
/// grovedb-merk 3.1.0 accepts: the forged subtree still hashes to the real root), or whose ops
/// don't decode or don't build exactly one tree.
pub fn check_layers(proof: &[u8]) -> Result<()> {
    fn walk(layer: &LayerProof) -> Result<()> {
        check_ops(&layer_ops(layer)?)?;
        layer.lower_layers.values().try_for_each(walk)
    }
    let GroveDBProof::V0(v0) = decode_envelope(proof)?;
    walk(&v0.root_layer)
}

/// Verify that `proof` proves an Item at `key` in the subtree at `path`, and return the root it
/// computes and the item's bytes. Nothing else passes: the proof must descend exactly `path`
/// ([`check_envelope`]), keep its opaque nodes childless ([`check_layers`]), carry the key's
/// element as one `KV` node (whose value its root binds), and verify under grovedb to exactly
/// that one Item at `path` and `key`. A proof that proves the key absent, a tree at the key, or
/// only a root hash (a lone `Push(Hash(root))`) is refused.
///
/// The root is the proof's own: the caller compares it with a root it trusts.
pub fn verify_item_at_path(
    proof: &[u8],
    path: &[Vec<u8>],
    key: &[u8],
) -> Result<([u8; 32], Vec<u8>)> {
    let fail = |m: String| WillowError::ProofVerificationFailed(m);
    if proof.is_empty() {
        return Err(fail("empty proof".into()));
    }
    check_envelope(proof, path)?;
    check_layers(proof)?;

    // The layer at `path` carries the key's element in a form the root binds.
    let GroveDBProof::V0(v0) = decode_envelope(proof)?;
    let mut layer = &v0.root_layer;
    for segment in path {
        layer = &layer.lower_layers[segment];
    }
    let mut carried = None;
    for op in layer_ops(layer)? {
        let (Op::Push(node) | Op::PushInverted(node)) = op else {
            continue;
        };
        let node_key = match &node {
            Node::KV(k, _)
            | Node::KVValueHash(k, ..)
            | Node::KVValueHashFeatureType(k, ..)
            | Node::KVRefValueHash(k, ..)
            | Node::KVDigest(k, _) => k,
            Node::Hash(_) | Node::KVHash(_) => continue,
        };
        if node_key.as_slice() != key {
            continue;
        }
        if carried.is_some() {
            return Err(fail("the proof carries the key twice".into()));
        }
        carried = Some(node);
    }
    let value =
        match carried {
            Some(Node::KV(_, value)) => value,
            Some(_) => return Err(fail(
                "the proof carries the key's element in a node whose root doesn't bind its value"
                    .into(),
            )),
            None => return Err(fail("the proof doesn't carry the key's element".into())),
        };

    let version = grovedb_version::version::GroveVersion::latest();
    let path_query = PathQuery::new_unsized(path.to_vec(), Query::new_single_key(key.to_vec()));
    let (root, results) = GroveDb::verify_query(proof, &path_query, version)
        .map_err(|e| fail(format!("GroveDB proof verification failed: {e}")))?;
    let [(result_path, result_key, Some(Element::Item(bytes, _)))] = results.as_slice() else {
        return Err(fail(
            "the proof doesn't prove exactly one item at the path and key".into(),
        ));
    };
    if result_path.as_slice() != path || result_key.as_slice() != key {
        return Err(fail(
            "the proof proves an item at another path or key".into(),
        ));
    }
    match Element::deserialize(&value, version) {
        Ok(Element::Item(carried_bytes, _)) if &carried_bytes == bytes => Ok((root, bytes.clone())),
        _ => Err(fail(
            "the item grovedb returns is not the one the proof's root binds".into(),
        )),
    }
}

/// Proofs built here for tests, in the shape grovedb's prover gives them.
#[cfg(test)]
pub(crate) mod test_proofs {
    use super::*;
    use grovedb_merk::tree::{
        combine_hash, kv_digest_to_kv_hash, kv_hash, node_hash, value_hash, NULL_HASH,
    };

    fn config() -> impl bincode2::config::Config {
        bincode2::config::standard()
            .with_big_endian()
            .with_no_limit()
    }

    pub(crate) fn encode_ops(ops: &[Op]) -> Vec<u8> {
        let mut bytes = vec![];
        for op in ops {
            ed::Encode::encode_into(op, &mut bytes).unwrap();
        }
        bytes
    }

    /// A proof that `value` is the Item at `key` under `path`, every layer one node, and the
    /// GroveDB root it proves.
    pub(crate) fn item_proof(path: &[Vec<u8>], key: &[u8], value: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let item = bincode2::encode_to_vec(Element::Item(value.to_vec(), None), config()).unwrap();
        let mut layer = LayerProof {
            merk_proof: encode_ops(&[Op::Push(Node::KV(key.to_vec(), item.clone()))]),
            lower_layers: Default::default(),
        };
        let kv = kv_hash(key, &item).unwrap();
        let mut root = node_hash(&kv, &NULL_HASH, &NULL_HASH).unwrap();
        let mut child_key = key.to_vec();
        for segment in path.iter().rev() {
            let tree =
                bincode2::encode_to_vec(Element::Tree(Some(child_key.clone()), None), config())
                    .unwrap();
            let hash = combine_hash(&value_hash(&tree).unwrap(), &root).unwrap();
            let mut lower_layers = std::collections::BTreeMap::new();
            lower_layers.insert(segment.clone(), layer);
            layer = LayerProof {
                merk_proof: encode_ops(&[Op::Push(Node::KVValueHash(segment.clone(), tree, hash))]),
                lower_layers,
            };
            let kv = kv_digest_to_kv_hash(segment, &hash).unwrap();
            root = node_hash(&kv, &NULL_HASH, &NULL_HASH).unwrap();
            child_key = segment.clone();
        }
        let proof = GroveDBProof::V0(grovedb::operations::proof::GroveDBProofV0 {
            root_layer: layer,
            prove_options: ProveOptions::default(),
        });
        (bincode2::encode_to_vec(proof, config()).unwrap(), root)
    }

    #[test]
    fn a_built_proof_verifies_under_grovedb() {
        let path = crate::proof::subgrove_data_path("sg-1");
        let (proof, root) = item_proof(&path, b"doc1", br#"{"a":1}"#);
        let pq = PathQuery::new_unsized(path.clone(), Query::new_single_key(b"doc1".to_vec()));
        let (computed, items) = GroveDb::verify_query(
            &proof,
            &pq,
            grovedb_version::version::GroveVersion::latest(),
        )
        .unwrap();
        assert_eq!(computed, root);
        assert_eq!(items.len(), 1);
        assert_eq!(
            verify_item_at_path(&proof, &path, b"doc1").unwrap(),
            (root, br#"{"a":1}"#.to_vec())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::test_proofs::encode_ops;
    use super::*;
    use crate::proof::ProofVerifier;
    use grovedb::{GroveDb, PathQuery, Query};
    use grovedb_version::version::GroveVersion;

    /// A real proof minted over the Willow indexed-data layout
    /// (`[subgroves, aave-v3-lending, indexed, Supply]`, one key). Framing:
    /// height u64 | root 32 | n_path u64 | (len u64 | seg)* | len u64 | query |
    /// limit u64 | offset u64 | len u64 | proof. All LE.
    struct Fixture {
        root: [u8; 32],
        path: Vec<Vec<u8>>,
        key: Vec<u8>,
        proof: Vec<u8>,
    }

    fn fixture() -> Fixture {
        let b = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/grovedb-single-key.bin"
        ))
        .expect("tests/fixtures/grovedb-single-key.bin");
        let mut o = 8;
        let u = |o: &mut usize| {
            let v = u64::from_le_bytes(b[*o..*o + 8].try_into().unwrap());
            *o += 8;
            v as usize
        };
        let bs = |o: &mut usize| {
            let n = u(o);
            let s = b[*o..*o + n].to_vec();
            *o += n;
            s
        };
        let root: [u8; 32] = b[o..o + 32].try_into().unwrap();
        o += 32;
        let n = u(&mut o);
        let path: Vec<Vec<u8>> = (0..n).map(|_| bs(&mut o)).collect();
        let query = bs(&mut o);
        let _limit = u(&mut o);
        let _offset = u(&mut o);
        let proof = bs(&mut o);
        assert_eq!(o, b.len());
        let key_len = query[3] as usize;
        let key = query[4..4 + key_len].to_vec();
        Fixture {
            root,
            path,
            key,
            proof,
        }
    }

    fn verify(proof: &[u8], path: &[Vec<u8>], key: &[u8]) -> Result<[u8; 32]> {
        check_envelope(proof, path)?;
        let pq = PathQuery::new_unsized(path.to_vec(), Query::new_single_key(key.to_vec()));
        GroveDb::verify_query(proof, &pq, GroveVersion::latest())
            .map(|(r, _)| r)
            .map_err(|e| WillowError::ProofVerificationFailed(e.to_string()))
    }

    fn last_index_of(hay: &[u8], needle: &[u8]) -> usize {
        hay.windows(needle.len())
            .rposition(|w| w == needle)
            .expect("needle")
    }

    #[test]
    fn honest_proof_passes_and_verifies_to_its_root() {
        let f = fixture();
        assert_eq!(verify(&f.proof, &f.path, &f.key).unwrap(), f.root);
    }

    #[test]
    fn renamed_lower_layer_is_the_omission_forgery() {
        let f = fixture();
        let mut forged = f.proof.clone();
        let i = last_index_of(&forged, &f.path[0]);
        forged[i] ^= 0x01;
        // grovedb alone accepts it: same root, result gone.
        let pq = PathQuery::new_unsized(f.path.clone(), Query::new_single_key(f.key.clone()));
        let (root, items) = GroveDb::verify_query(&forged, &pq, GroveVersion::latest()).unwrap();
        assert_eq!(root, f.root);
        assert!(items.iter().all(|(_, _, e)| e.is_none()));
        // With the envelope check it is refused.
        let err = verify(&forged, &f.path, &f.key).unwrap_err().to_string();
        assert!(err.contains("does not descend"), "{err}");
    }

    #[test]
    fn dropped_lower_layer_is_refused() {
        let f = fixture();
        let config = bincode2::config::standard()
            .with_big_endian()
            .with_no_limit();
        let (GroveDBProof::V0(mut v0), _): (GroveDBProof, usize) =
            bincode2::decode_from_slice(&f.proof, config).unwrap();
        let mut layer = &mut v0.root_layer;
        for seg in &f.path[..f.path.len() - 1] {
            layer = layer.lower_layers.get_mut(seg).unwrap();
        }
        assert!(layer
            .lower_layers
            .remove(&f.path[f.path.len() - 1])
            .is_some());
        let forged = bincode2::encode_to_vec(GroveDBProof::V0(v0), config).unwrap();
        let err = verify(&forged, &f.path, &f.key).unwrap_err().to_string();
        assert!(err.contains("does not descend"), "{err}");
    }

    #[test]
    fn non_default_prove_options_are_refused() {
        let f = fixture();
        let mut forged = f.proof.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0x01;
        let err = verify(&forged, &f.path, &f.key).unwrap_err().to_string();
        assert!(err.contains("prove_options"), "{err}");
    }

    fn config() -> impl bincode2::config::Config {
        bincode2::config::standard()
            .with_big_endian()
            .with_no_limit()
    }

    /// The fixture's envelope with its leaf layer's ops replaced by `edit(ops)`.
    fn with_leaf_ops(f: &Fixture, edit: impl FnOnce(&mut Vec<Op>)) -> Vec<u8> {
        let (GroveDBProof::V0(mut v0), _): (GroveDBProof, usize) =
            bincode2::decode_from_slice(&f.proof, config()).unwrap();
        let mut layer = &mut v0.root_layer;
        for seg in &f.path {
            layer = layer.lower_layers.get_mut(seg).unwrap();
        }
        let mut ops = layer_ops(layer).unwrap();
        edit(&mut ops);
        layer.merk_proof = encode_ops(&ops);
        bincode2::encode_to_vec(GroveDBProof::V0(v0), config()).unwrap()
    }

    fn forged_item() -> Vec<u8> {
        bincode2::encode_to_vec(Element::Item(b"forged".to_vec(), None), config()).unwrap()
    }

    /// The single-key query grovedb alone verifies: its root and the element it returns.
    fn grovedb_alone(f: &Fixture, proof: &[u8]) -> ([u8; 32], Option<Element>) {
        let pq = PathQuery::new_unsized(f.path.clone(), Query::new_single_key(f.key.clone()));
        let (root, mut items) = GroveDb::verify_query(proof, &pq, GroveVersion::latest()).unwrap();
        (root, items.pop().and_then(|(_, _, e)| e))
    }

    #[test]
    fn an_honest_proof_binds_its_item_at_the_path_and_key() {
        let f = fixture();
        let (root, bytes) = verify_item_at_path(&f.proof, &f.path, &f.key).unwrap();
        assert_eq!(root, f.root);
        let (_, element) = grovedb_alone(&f, &f.proof);
        assert_eq!(element, Some(Element::Item(bytes, None)));
        // Another key or another path under the same proof proves nothing.
        assert!(verify_item_at_path(&f.proof, &f.path, b"another-key").is_err());
        let mut other_path = f.path.clone();
        *other_path.last_mut().unwrap() = b"Borrow".to_vec();
        assert!(verify_item_at_path(&f.proof, &other_path, &f.key).is_err());
    }

    /// `00 21 01 <root> 00 01`: a V0 envelope whose root layer is the one op `Push(Hash(root))`
    /// and no lower layers, under the default prove options. It "verifies" to any root it names.
    #[test]
    fn a_lone_root_hash_proves_nothing() {
        let f = fixture();
        let mut lone = vec![0x00, 0x21, 0x01];
        lone.extend_from_slice(&f.root);
        lone.extend_from_slice(&[0x00, 0x01]);
        let GroveDBProof::V0(v0) = decode_envelope(&lone).unwrap();
        assert_eq!(
            layer_ops(&v0.root_layer).unwrap(),
            vec![Op::Push(Node::Hash(f.root))]
        );
        for path in [vec![], f.path.clone()] {
            for key in [f.key.clone(), b"subgroves".to_vec()] {
                assert!(
                    verify_item_at_path(&lone, &path, &key).is_err(),
                    "{path:?} {key:?}"
                );
            }
        }
    }

    /// grovedb-merk 3.1.0 takes an opaque Hash node's hash as given, children or not: a forged
    /// KV attached under the layer's root hash keeps the root and is read as the answer.
    #[test]
    fn a_child_under_an_opaque_hash_node_is_refused() {
        let f = fixture();
        // The leaf layer's own root, from its honest ops.
        let leaf_root = {
            let (GroveDBProof::V0(v0), _): (GroveDBProof, usize) =
                bincode2::decode_from_slice(&f.proof, config()).unwrap();
            let mut layer = &v0.root_layer;
            for seg in &f.path {
                layer = &layer.lower_layers[seg];
            }
            Query::new_single_key(f.key.clone())
                .execute_proof(&layer.merk_proof, None, true)
                .unwrap()
                .unwrap()
                .0
        };
        let forged = with_leaf_ops(&f, |ops| {
            *ops = vec![
                Op::Push(Node::Hash(leaf_root)),
                Op::Push(Node::KV(f.key.clone(), forged_item())),
                Op::Child,
            ];
        });
        // grovedb alone accepts it: the real root, and the forged item as the answer.
        let (root, element) = grovedb_alone(&f, &forged);
        assert_eq!(root, f.root);
        assert_eq!(element, Some(Element::Item(b"forged".to_vec(), None)));
        // Refused before verifying.
        let err = verify_item_at_path(&forged, &f.path, &f.key)
            .unwrap_err()
            .to_string();
        assert!(err.contains("opaque Hash"), "{err}");
        assert!(check_layers(&forged).is_err());
        assert!(check_layers(&f.proof).is_ok());
    }

    /// A KVValueHash node's value is not hashed into the root: forged bytes beside the honest
    /// value hash keep the root.
    #[test]
    fn an_item_whose_value_the_root_does_not_bind_is_refused() {
        let f = fixture();
        let forged = with_leaf_ops(&f, |ops| {
            for op in ops.iter_mut() {
                if let Op::Push(Node::KV(k, v)) = op {
                    if *k == f.key {
                        let hash = grovedb_merk::tree::value_hash(v).unwrap();
                        *op = Op::Push(Node::KVValueHash(k.clone(), forged_item(), hash));
                    }
                }
            }
        });
        let (root, element) = grovedb_alone(&f, &forged);
        assert_eq!(root, f.root);
        assert_eq!(element, Some(Element::Item(b"forged".to_vec(), None)));
        let err = verify_item_at_path(&forged, &f.path, &f.key)
            .unwrap_err()
            .to_string();
        assert!(err.contains("doesn't bind its value"), "{err}");
    }

    #[test]
    fn proof_deeper_than_the_path_is_refused() {
        let f = fixture();
        let err = check_envelope(&f.proof, &f.path[..3])
            .unwrap_err()
            .to_string();
        assert!(err.contains("below the query path"), "{err}");
        // Checked at the empty path, a proof over a real data path is refused too.
        let err = ProofVerifier::verify_item_at_path(&hex::encode(&f.proof), &[], &f.key, b"")
            .unwrap_err()
            .to_string();
        assert!(err.contains("below the query path"), "{err}");
    }
}
