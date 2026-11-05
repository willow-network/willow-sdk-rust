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
//!
//! grovedb 3.1.0 decodes a proof, and the elements in it, with bincode and no
//! size limit: a byte string is allocated at its claimed length before it is
//! read, and each level of layer nesting takes another stack frame, so a
//! hostile proof can abort the process. Before grovedb sees a proof, the
//! envelope is bounds-checked without recursion (at most [`MAX_PROOF_BYTES`],
//! every length within the bytes left, at most [`MAX_LAYER_DEPTH`] levels and
//! [`MAX_LAYERS`] layers) and every node value is decoded as an element within
//! its own size; a proof that fails is refused.
//!
//! A merk op takes one byte on the wire and over a hundred in memory, so the
//! SDK checks a layer's ops one at a time as it decodes them and never collects
//! them. grovedb-merk 3.1.0 holds every node a layer pushes until its `Parent`
//! and `Child` ops fold them; [`MAX_PROOF_BYTES`] bounds how many it can hold.

use crate::errors::{Result, WillowError};
use grovedb::operations::proof::{GroveDBProof, GroveDBProofV0, LayerProof, ProveOptions};
use grovedb::{Element, GroveDb, PathQuery, Query};
use grovedb_merk::proofs::{Decoder, Node, Op};

/// The deepest a proof's layers may nest below its root layer. A GroveDB path is a handful of
/// segments; bincode decodes each level of nesting with one more stack frame.
pub const MAX_LAYER_DEPTH: usize = 64;

/// The most layers a proof may carry in all.
pub const MAX_LAYERS: usize = 1024;

/// The largest proof envelope accepted, in bytes: 1 MiB.
///
/// The proofs the SDK verifies prove one key: the API's `/proof` and the verifiable RPC's entity
/// proofs are single-key queries. Each layer of one carries the queried node, whose value
/// grovedb-merk 3.1.0 encodes with a u16 length (so under 64 KiB), and the hashes on the path
/// to it, about 70 bytes a level (a few KiB for a tree of billions of keys), over a path of
/// four or five layers: an honest proof is under 400 KiB even with a 64 KiB node in every
/// layer, and a few KiB with small values. The cap bounds what a hostile proof costs to check,
/// here and in grovedb, which holds every node a layer pushes until its ops fold them: at
/// 1 MiB, about 90,000 nodes and some tens of MiB.
pub const MAX_PROOF_BYTES: usize = 1 << 20;

/// What bincode may claim while decoding an envelope that passed [`scan_envelope`]: the lengths
/// of its byte strings (at most the envelope's size), and, for each map of lower layers still
/// being read, its remaining entries' size.
const ENVELOPE_DECODE_LIMIT: usize =
    MAX_PROOF_BYTES + MAX_LAYERS * std::mem::size_of::<(Vec<u8>, LayerProof)>();

/// The largest merk node value: its length is a u16.
const MAX_ELEMENT_BYTES: usize = u16::MAX as usize;

/// The length of an element a proof can't tell from a subtree or a reference. A node's value
/// hash is blake3 over the value's length (a varint) and the value; a subtree's or a
/// reference's is `combine_hash`, blake3 over two 32-byte hashes. For a 63-byte value the two
/// inputs are both 64 bytes, so a `KV` node of 63 bytes can stand for a subtree or reference
/// whose hashes are ground to match.
const AMBIGUOUS_ELEMENT_LEN: usize = 63;

fn envelope_error(m: impl std::fmt::Display) -> WillowError {
    WillowError::ProofVerificationFailed(format!("GroveDB envelope: {m}"))
}

/// Reject a proof envelope that does not descend `path`, carries layers below
/// it, or sets non-default prove options.
pub fn check_envelope(proof: &[u8], path: &[Vec<u8>]) -> Result<()> {
    layer_at_path(&decode_envelope(proof)?, path).map(|_| ())
}

/// The layer of `v0` at `path`, which the envelope must descend with no layer below it, under
/// the default prove options.
fn layer_at_path<'a>(v0: &'a GroveDBProofV0, path: &[Vec<u8>]) -> Result<&'a LayerProof> {
    if v0.prove_options.decrease_limit_on_empty_sub_query_result
        != ProveOptions::default().decrease_limit_on_empty_sub_query_result
    {
        return Err(envelope_error("non-default prove_options"));
    }
    let mut layer: &LayerProof = &v0.root_layer;
    for (depth, seg) in path.iter().enumerate() {
        layer = layer.lower_layers.get(seg).ok_or_else(|| {
            envelope_error(format!(
                "no lower layer for path segment {depth} ({}); the proof does not descend to the query path",
                String::from_utf8_lossy(seg)
            ))
        })?;
    }
    if !layer.lower_layers.is_empty() {
        return Err(envelope_error(
            "unexpected lower layers below the query path",
        ));
    }
    Ok(layer)
}

/// The path a proof descends: from the root layer, the key of each layer's one lower layer,
/// until a layer has none. A layer with more than one lower layer is refused.
pub fn descended_path(proof: &[u8]) -> Result<Vec<Vec<u8>>> {
    let v0 = decode_envelope(proof)?;
    let mut path = vec![];
    let mut layer = &v0.root_layer;
    while let Some((key, lower)) = layer.lower_layers.iter().next() {
        if layer.lower_layers.len() > 1 {
            return Err(envelope_error("a layer with more than one lower layer"));
        }
        path.push(key.clone());
        layer = lower;
    }
    Ok(path)
}

/// Bounds-check an envelope's encoding before anything decodes it, without recursion: a V0
/// envelope (bincode 2, big-endian varints) whose every length fits in the bytes left, whose
/// layers nest at most [`MAX_LAYER_DEPTH`] deep and number at most [`MAX_LAYERS`], then a
/// boolean, then nothing. bincode (grovedb's decoder included) resizes a byte string to its
/// claimed length before reading it, and decodes each level of nesting one stack frame deeper,
/// so an unchecked envelope can make it allocate without bound or overflow the stack, which
/// aborts the process.
fn scan_envelope(proof: &[u8]) -> Result<()> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(envelope_error(format!(
            "{} bytes; at most {MAX_PROOF_BYTES} are accepted",
            proof.len()
        )));
    }
    let mut scan = Scan { bytes: proof };
    if scan.varint()? != 0 {
        return Err(envelope_error("not a V0 proof"));
    }
    // For each layer being read, from the root down: how many of its lower layers are left.
    let mut open: Vec<u64> = Vec::new();
    let mut layers = 0usize;
    'layer: loop {
        layers += 1;
        if layers > MAX_LAYERS {
            return Err(envelope_error(format!("more than {MAX_LAYERS} layers")));
        }
        if open.len() > MAX_LAYER_DEPTH {
            return Err(envelope_error(format!(
                "layers nest deeper than {MAX_LAYER_DEPTH}"
            )));
        }
        let merk_proof = scan.len()?;
        scan.skip(merk_proof)?;
        let lower = scan.varint()?;
        // A lower layer takes at least 3 bytes: its key's length, its ops' length, and its count.
        if lower > (scan.bytes.len() / 3) as u64 {
            return Err(envelope_error(format!(
                "{lower} lower layers in {} bytes",
                scan.bytes.len()
            )));
        }
        open.push(lower);
        while let Some(left) = open.last().copied() {
            if left == 0 {
                open.pop();
                continue;
            }
            *open.last_mut().expect("an open layer") = left - 1;
            let key = scan.len()?;
            scan.skip(key)?;
            continue 'layer;
        }
        break;
    }
    match scan.take(1)? {
        [0] | [1] => {}
        _ => return Err(envelope_error("prove_options is not a boolean")),
    }
    if !scan.bytes.is_empty() {
        return Err(envelope_error(format!(
            "{} trailing bytes",
            scan.bytes.len()
        )));
    }
    Ok(())
}

/// The bytes of an envelope not yet scanned.
struct Scan<'a> {
    bytes: &'a [u8],
}

impl<'a> Scan<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.bytes.len() {
            return Err(envelope_error(format!(
                "a length of {n} with {} bytes left",
                self.bytes.len()
            )));
        }
        let (taken, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(taken)
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    /// bincode 2's varint: one byte below 251, else 251, 252, or 253 then a big-endian u16, u32,
    /// or u64.
    fn varint(&mut self) -> Result<u64> {
        let width = match self.take(1)?[0] {
            b @ 0..=250 => return Ok(b as u64),
            251 => 2,
            252 => 4,
            253 => 8,
            b => return Err(envelope_error(format!("varint tag {b}"))),
        };
        Ok(self
            .take(width)?
            .iter()
            .fold(0u64, |v, b| (v << 8) | *b as u64))
    }

    /// A byte string's length, which must fit in the bytes left.
    fn len(&mut self) -> Result<usize> {
        let n = self.varint()?;
        if n > self.bytes.len() as u64 {
            return Err(envelope_error(format!(
                "a length of {n} with {} bytes left",
                self.bytes.len()
            )));
        }
        Ok(n as usize)
    }
}

/// The proof envelope, refusing trailing bytes. Only an envelope [`scan_envelope`] passes is
/// decoded, so grovedb's own decoding of the same bytes is bounded too.
fn decode_envelope(proof: &[u8]) -> Result<GroveDBProofV0> {
    scan_envelope(proof)?;
    let config = bincode2::config::standard()
        .with_big_endian()
        .with_limit::<ENVELOPE_DECODE_LIMIT>();
    let (envelope, used): (GroveDBProof, usize) =
        bincode2::decode_from_slice(proof, config).map_err(envelope_error)?;
    if used != proof.len() {
        return Err(envelope_error(format!(
            "{} trailing bytes",
            proof.len() - used
        )));
    }
    let GroveDBProof::V0(v0) = envelope;
    Ok(v0)
}

/// A merk node's value as the GroveDB element it encodes, decoded within the value's own size
/// bound. grovedb decodes the values it reads with no limit, so a value that claims more than
/// it holds is refused here before grovedb sees it.
fn decode_element(value: &[u8]) -> Result<Element> {
    if value.len() > MAX_ELEMENT_BYTES {
        return Err(WillowError::ProofVerificationFailed(format!(
            "GroveDB layer: a node value of {} bytes",
            value.len()
        )));
    }
    let config = bincode2::config::standard()
        .with_big_endian()
        .with_limit::<MAX_ELEMENT_BYTES>();
    bincode2::decode_from_slice::<Element, _>(value, config)
        .map(|(element, _)| element)
        .map_err(|e| {
            WillowError::ProofVerificationFailed(format!(
                "GroveDB layer: a node value that is not an element: {e}"
            ))
        })
}

/// One layer's merk ops, decoded one at a time as they are read and never collected (an op
/// is as little as one byte on the wire and over a hundred in memory); bytes that don't decode
/// are an error.
fn layer_ops(layer: &LayerProof) -> impl Iterator<Item = Result<Op>> + '_ {
    Decoder::new(&layer.merk_proof).map(|op| {
        op.map_err(|e| WillowError::ProofVerificationFailed(format!("GroveDB layer: {e}")))
    })
}

/// Refuse a layer whose ops attach a child to an opaque `Hash` node, or don't build one tree,
/// or carry a value that doesn't decode as an element within its size. The ops are checked as
/// they are decoded, and the first that fails ends the check.
fn check_ops(ops: impl Iterator<Item = Result<Op>>) -> Result<()> {
    let fail = |m: &str| {
        Err(WillowError::ProofVerificationFailed(format!(
            "GroveDB layer: {m}"
        )))
    };
    // Each stack entry: whether the node at the top of that subtree is an opaque Hash.
    let mut stack: Vec<bool> = Vec::new();
    for op in ops {
        match op? {
            Op::Push(node) | Op::PushInverted(node) => {
                match &node {
                    Node::KV(_, value)
                    | Node::KVValueHash(_, value, _)
                    | Node::KVValueHashFeatureType(_, value, ..)
                    | Node::KVRefValueHash(_, value, _) => {
                        decode_element(value)?;
                    }
                    Node::Hash(_) | Node::KVHash(_) | Node::KVDigest(..) => {}
                }
                stack.push(matches!(node, Node::Hash(_)))
            }
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
/// don't decode or don't build exactly one tree, or carry a value that isn't an element within
/// its size (which grovedb would decode with no limit).
pub fn check_layers(proof: &[u8]) -> Result<()> {
    check_all_layers(&decode_envelope(proof)?)
}

fn check_all_layers(v0: &GroveDBProofV0) -> Result<()> {
    let mut layers = vec![&v0.root_layer];
    while let Some(layer) = layers.pop() {
        check_ops(layer_ops(layer))?;
        layers.extend(layer.lower_layers.values());
    }
    Ok(())
}

/// Whether the subtree at `path` holds only Items: a subgrove's data tree
/// (`[subgroves, <subgrove id>, data]`), where the chain stores each key's value as an Item.
fn holds_only_items(path: &[Vec<u8>]) -> bool {
    matches!(path, [subgroves, _, data] if subgroves == b"subgroves" && data == b"data")
}

/// Verify that `proof` proves an Item at `key` in the subtree at `path`, and return the root it
/// computes and the item's bytes. Nothing else passes: the proof must descend exactly `path`
/// ([`check_envelope`]), keep its opaque nodes childless and its values elements within their
/// size ([`check_layers`]), carry the key's element as one `KV` node (whose value its root
/// binds), and verify under grovedb to exactly that one Item at `path` and `key`. A proof that
/// proves the key absent, a tree at the key, or only a root hash (a lone `Push(Hash(root))`) is
/// refused. So is an element of exactly 63 bytes (an Item with a 60-byte value and no flags),
/// whose `KV` node a proof can't tell from a subtree's or a reference's, except in a subgrove's
/// data tree (`[subgroves, <subgrove id>, data]`), which holds only Items.
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
    let v0 = decode_envelope(proof)?;
    let layer = layer_at_path(&v0, path)?;
    check_all_layers(&v0)?;

    // The layer at `path` carries the key's element in a form the root binds.
    let mut carried = None;
    for op in layer_ops(layer) {
        let (Op::Push(node) | Op::PushInverted(node)) = op? else {
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
    if value.len() == AMBIGUOUS_ELEMENT_LEN && !holds_only_items(path) {
        return Err(fail(format!(
            "the key's element is {AMBIGUOUS_ELEMENT_LEN} bytes, which a proof can't tell from a \
             subtree or a reference outside a subgrove's data tree"
        )));
    }

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
    match decode_element(&value) {
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
        let mut ops: Vec<Op> = layer_ops(layer).collect::<Result<_>>().unwrap();
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
        let v0 = decode_envelope(&lone).unwrap();
        assert_eq!(
            layer_ops(&v0.root_layer)
                .collect::<Result<Vec<_>>>()
                .unwrap(),
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

    /// An Item with a 60-byte value and no flags is 63 bytes, the length whose `KV` node a proof
    /// can't tell from a subtree's or a reference's: refused outside a subgrove's data tree,
    /// accepted in it, where the chain stores only Items.
    #[test]
    fn a_63_byte_element_is_refused_outside_a_subgroves_data_tree() {
        use super::test_proofs::item_proof;
        let value = [b'v'; 60];
        let entity_tree = vec![
            b"subgroves".to_vec(),
            b"sg-1".to_vec(),
            b"indexed".to_vec(),
            b"Supply".to_vec(),
        ];
        let (proof, _) = item_proof(&entity_tree, b"k", &value);
        let err = verify_item_at_path(&proof, &entity_tree, b"k")
            .unwrap_err()
            .to_string();
        assert!(err.contains("63 bytes"), "{err}");
        assert!(ProofVerifier::verify_item_at_path(
            &hex::encode(&proof),
            &entity_tree,
            b"k",
            &value
        )
        .is_err());
        for n in [59, 61] {
            let other = vec![b'v'; n];
            let (proof, root) = item_proof(&entity_tree, b"k", &other);
            assert_eq!(
                verify_item_at_path(&proof, &entity_tree, b"k").unwrap(),
                (root, other)
            );
        }
        let data = crate::proof::subgrove_data_path("sg-1");
        let (proof, root) = item_proof(&data, b"k", &value);
        assert_eq!(
            verify_item_at_path(&proof, &data, b"k").unwrap(),
            (root, value.to_vec())
        );
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

/// Proofs built to crash a decoder that trusts their lengths or nesting, through every public
/// verifier that takes a proof.
#[cfg(all(test, feature = "verifiable-rpc", not(feature = "no-light-client")))]
mod hostile_proofs {
    use super::test_proofs::{encode_ops, item_proof};
    use super::*;
    use crate::light_client::{LightClient, LightClientConfig};
    use crate::proof::ProofVerifier;
    use crate::types::SignatureAlgorithm;
    use crate::WillowClient;
    use serde_json::json;
    use std::time::Duration;
    use willow_types::verifiable_rpc::VerifiableRpcResponse;
    use wiremock::matchers::{method, path as url_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const CASE: &str = "WILLOW_HOSTILE_PROOF_CASE";
    const SG: &str = "sg-1";
    const KEY: &[u8] = b"doc1";

    /// A V0 envelope whose root layer's ops claim `len` bytes and hold none.
    fn allocation(len: u64) -> Vec<u8> {
        [&[0x00, 0xFD][..], &len.to_be_bytes()].concat()
    }

    /// A well-formed V0 envelope whose layers nest `depth` deep, each the one lower layer of the
    /// one above it, under an empty key.
    fn nesting(depth: usize) -> Vec<u8> {
        let mut proof = vec![0x00];
        for _ in 0..depth {
            proof.extend_from_slice(&[0x00, 0x01, 0x00]);
        }
        proof.extend_from_slice(&[0x00, 0x00, 0x01]);
        proof
    }

    /// A well-formed proof of KEY at `path` whose leaf `KV` node's value is an Item claiming
    /// `len` bytes and holding none.
    fn element(path: &[Vec<u8>], len: u64) -> Vec<u8> {
        let (honest, _) = item_proof(path, KEY, b"{}");
        let config = bincode2::config::standard()
            .with_big_endian()
            .with_no_limit();
        let (GroveDBProof::V0(mut v0), _): (GroveDBProof, usize) =
            bincode2::decode_from_slice(&honest, config).unwrap();
        let mut layer = &mut v0.root_layer;
        for segment in path {
            layer = layer.lower_layers.get_mut(segment).unwrap();
        }
        let value = [&[0x00, 0xFD][..], &len.to_be_bytes()].concat();
        layer.merk_proof = encode_ops(&[Op::Push(Node::KV(KEY.to_vec(), value))]);
        bincode2::encode_to_vec(GroveDBProof::V0(v0), config).unwrap()
    }

    fn entity_path() -> Vec<Vec<u8>> {
        vec![
            b"subgroves".to_vec(),
            SG.as_bytes().to_vec(),
            b"indexed".to_vec(),
            b"Supply".to_vec(),
        ]
    }

    fn payload(name: &str, path: &[Vec<u8>]) -> Vec<u8> {
        match name {
            // Claims that fail to allocate at once, so the unfixed decoder aborts without
            // touching memory.
            "alloc" => allocation(1 << 62),
            "element" => element(path, 1 << 62),
            // The reviewed payloads: a 2^40-byte claim.
            "alloc-2^40" => allocation(1 << 40),
            "element-2^40" => element(path, 1 << 40),
            "nest" => nesting(200_000),
            other => panic!("no payload {other}"),
        }
    }

    /// Serve `proof` through `call`, one of the public verifiers.
    async fn run(name: &str, call: &str) -> Result<()> {
        match call {
            "proof_verifier" => {
                let path = entity_path();
                let proof = payload(name, &path);
                ProofVerifier::verify_item_at_path(&hex::encode(proof), &path, KEY, b"{}")
                    .map(|_| ())
            }
            "light_client" => {
                let path = entity_path();
                let proof = payload(name, &path);
                let light_client = LightClient::new(
                    LightClientConfig::builder("willow")
                        .validator_endpoints(vec!["http://127.0.0.1:1".into()])
                        .rpc_timeout(Duration::from_millis(200))
                        .build(),
                )?;
                light_client
                    .verify_item(&proof, &path, KEY, b"{}", 41)
                    .await
                    .map(|_| ())
            }
            "data_get" => {
                let proof = payload(name, &crate::proof::subgrove_data_path(SG));
                let server = MockServer::start().await;
                Mock::given(method("GET"))
                    .and(url_path("/data/sg-1/doc1"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"success": true, "data": {}})),
                    )
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(url_path("/proof/sg-1/doc1"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "success": true,
                        "data": {"proof": hex::encode(proof), "height": 41}
                    })))
                    .mount(&server)
                    .await;
                let client = WillowClient::builder()
                    .api_url(&server.uri())
                    .light_client_config(
                        LightClientConfig::builder("willow")
                            .validator_endpoints(vec![server.uri()])
                            .rpc_timeout(Duration::from_millis(200))
                            .build(),
                    )
                    .build()
                    .await?;
                client.set_identity_with_algorithm(
                    "did:willow:a",
                    &"03".repeat(32),
                    "did:willow:a#key-1",
                    SignatureAlgorithm::Ed25519,
                );
                client.data().get(SG, "doc1").await.map(|_| ())
            }
            "verifiable_rpc" => {
                let proof = payload(name, &entity_path());
                let response = VerifiableRpcResponse {
                    subgrove_id: SG.into(),
                    key: KEY.to_vec(),
                    answer: b"{}".to_vec(),
                    answer_exists: true,
                    checkpoint_id: [0; 32],
                    state_root: [0; 32],
                    block_range: (1, 2),
                    grovedb_proof: proof,
                    gkr_proofs: vec![],
                    completeness_proof: None,
                    state_proofs: vec![],
                    served_at_unix_secs: 1,
                };
                let server = MockServer::start().await;
                Mock::given(method("GET"))
                    .and(url_path(format!(
                        "/verifiable-rpc/{SG}/{}",
                        hex::encode(KEY)
                    )))
                    .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                    .mount(&server)
                    .await;
                let client = WillowClient::builder()
                    .api_url(&server.uri())
                    .indexer_url(&server.uri())
                    .build()
                    .await?;
                client.verifiable_rpc().query(SG, KEY).await.map(|_| ())
            }
            other => panic!("no call {other}"),
        }
    }

    const CALLS: [&str; 4] = [
        "proof_verifier",
        "light_client",
        "data_get",
        "verifiable_rpc",
    ];

    /// Run each case in a child process (this test binary, running [`one_case`]), so a case that
    /// aborts the process (an allocation that fails, a stack overflow) fails this test with the
    /// child's exit status rather than ending the test run.
    fn run_cases(payloads: &[&str]) {
        let exe = std::env::current_exe().unwrap();
        let mut failures = vec![];
        for payload in payloads {
            for call in CALLS {
                let case = format!("{payload}/{call}");
                let out = std::process::Command::new(&exe)
                    .args([
                        "--exact",
                        "grovedb_envelope::hostile_proofs::one_case",
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CASE, &case)
                    .output()
                    .unwrap();
                let stderr = String::from_utf8_lossy(&out.stderr);
                let ran = String::from_utf8_lossy(&out.stdout).contains("1 passed");
                if !out.status.success() || !ran {
                    let tail: Vec<&str> = stderr.lines().rev().take(2).collect();
                    failures.push(format!(
                        "{case}: {} ({})",
                        out.status,
                        tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "hostile proofs not refused:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn hostile_proofs_are_refused_by_every_verifier_without_crashing() {
        run_cases(&["alloc", "nest", "element"]);
    }

    #[test]
    fn the_reviewed_two_to_the_forty_payloads_are_refused() {
        run_cases(&["alloc-2^40", "element-2^40"]);
    }

    /// One case of the tests above, named by the environment; does nothing without it.
    #[tokio::test]
    #[ignore = "a case of the hostile-proof tests, which run it in a child process"]
    async fn one_case() {
        let Ok(case) = std::env::var(CASE) else {
            return;
        };
        let (name, call) = case.split_once('/').unwrap();
        let result = run(name, call).await;
        assert!(
            matches!(result, Err(WillowError::ProofVerificationFailed(_))),
            "{case}: {result:?}"
        );
    }

    #[test]
    fn the_envelope_scan_bounds_nesting_layers_and_values() {
        assert!(decode_envelope(&nesting(64)).is_ok());
        let err = decode_envelope(&nesting(65)).err().unwrap().to_string();
        assert!(err.contains("nest deeper"), "{err}");
        // A root layer with 1024 lower layers is 1025 layers, one too many.
        let mut wide = vec![0x00, 0x00, 0xFB];
        wide.extend_from_slice(&1024u16.to_be_bytes());
        for i in 0..1024u16 {
            wide.push(0x02);
            wide.extend_from_slice(&i.to_be_bytes());
            wide.extend_from_slice(&[0x00, 0x00]);
        }
        wide.push(0x01);
        let err = decode_envelope(&wide).err().unwrap().to_string();
        assert!(err.contains("more than 1024 layers"), "{err}");
        // A value that isn't an element within its size, anywhere in the proof.
        let err = check_layers(&element(&entity_path(), 1 << 62))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not an element"), "{err}");
    }

    fn encode(v0: GroveDBProofV0) -> Vec<u8> {
        let config = bincode2::config::standard()
            .with_big_endian()
            .with_no_limit();
        bincode2::encode_to_vec(GroveDBProof::V0(v0), config).unwrap()
    }

    /// A V0 envelope of about `bytes` bytes whose root layer is that many one-byte `Parent` ops,
    /// with a one-op layer below it for each segment of `path`.
    fn parent_ops(path: &[Vec<u8>], bytes: usize) -> Vec<u8> {
        let mut layer = LayerProof {
            merk_proof: vec![0x10],
            lower_layers: Default::default(),
        };
        for (i, segment) in path.iter().enumerate().rev() {
            let ops = if i == 0 {
                vec![0x10; bytes]
            } else {
                vec![0x10]
            };
            layer = LayerProof {
                merk_proof: ops,
                lower_layers: [(segment.clone(), layer)].into(),
            };
        }
        encode(GroveDBProofV0 {
            root_layer: layer,
            prove_options: ProveOptions::default(),
        })
    }

    /// The honest proof of KEY at `path`, its leaf layer's ops replaced by about `bytes` bytes
    /// of `Push(KV(k, item))` ops, the 3-byte keys `k` ascending, then a `Child` op for each
    /// push after the first: one tree, every value an element, which grovedb-merk holds node by
    /// node until the `Child` ops fold them. Returns the proof and the last key.
    fn pushed_nodes(path: &[Vec<u8>], bytes: usize) -> (Vec<u8>, Vec<u8>) {
        let (honest, _) = item_proof(path, KEY, b"{}");
        let config = bincode2::config::standard()
            .with_big_endian()
            .with_no_limit();
        let (GroveDBProof::V0(mut v0), _): (GroveDBProof, usize) =
            bincode2::decode_from_slice(&honest, config).unwrap();
        let mut layer = &mut v0.root_layer;
        for segment in path {
            layer = layer.lower_layers.get_mut(segment).unwrap();
        }
        let item = bincode2::encode_to_vec(Element::Item(vec![], None), config).unwrap();
        // 0x03, key length, key, value length (2 bytes), value; and the node's Child op.
        let nodes = bytes / (1 + 1 + 3 + 2 + item.len() + 1);
        let key = |i: usize| (i as u32).to_be_bytes()[1..].to_vec();
        let mut ops = Vec::with_capacity(bytes);
        for i in 0..nodes {
            ed::Encode::encode_into(&Op::Push(Node::KV(key(i), item.clone())), &mut ops).unwrap();
        }
        ops.resize(ops.len() + nodes - 1, 0x11);
        layer.merk_proof = ops;
        (encode(v0), key(nodes - 1))
    }

    /// Inside the 32 MiB the scan used to accept, a proof of one-byte ops decodes to an `Op`
    /// of at least 104 bytes each: about 33.5M `Parent` ops in its root layer, or about 3M
    /// pushed nodes, which grovedb-merk holds (about 208 bytes and two heap allocations each)
    /// before any root check. Both are refused by their size before anything decodes them.
    #[test]
    fn proofs_of_millions_of_ops_are_refused_before_they_decode() {
        let data = crate::proof::subgrove_data_path(SG);
        let old_cap = 32 << 20;
        let parents = parent_ops(&data, old_cap - 64);
        let (pushes, _) = pushed_nodes(&data, old_cap - 1024);
        for (name, proof) in [("parent ops", parents), ("pushed nodes", pushes)] {
            assert!(proof.len() <= old_cap, "{name}: {}", proof.len());
            let err = decode_envelope(&proof).err().map(|e| e.to_string());
            assert!(
                err.as_deref().is_some_and(|e| e.contains("are accepted")),
                "{name} of {} bytes: {err:?}",
                proof.len()
            );
        }
    }

    /// Under the cap, a proof's ops are checked one at a time, never collected: a root layer
    /// of a million `Parent` ops is refused at the first, with no memory to speak of. A layer
    /// of pushed nodes that passes every check reaches grovedb, which holds them; the cap
    /// bounds that.
    #[test]
    fn a_proof_of_many_ops_under_the_cap_is_refused_in_bounded_memory() {
        use super::alloc_meter::peak;
        let data = crate::proof::subgrove_data_path(SG);
        let parents = parent_ops(&data, 1_000_000);
        let (result, held) = peak(|| verify_item_at_path(&parents, &data, KEY));
        eprintln!("parent ops: {} bytes, peak {held} bytes", parents.len());
        assert!(
            matches!(result, Err(WillowError::ProofVerificationFailed(_))),
            "{result:?}"
        );
        assert!(
            held < 4 << 20,
            "{held} bytes held for {} bytes of ops",
            parents.len()
        );

        let (pushes, last) = pushed_nodes(&data, 1_000_000);
        let (result, held) = peak(|| verify_item_at_path(&pushes, &data, &last));
        eprintln!("pushed nodes: {} bytes, peak {held} bytes", pushes.len());
        assert!(
            matches!(result, Err(WillowError::ProofVerificationFailed(_))),
            "{result:?}"
        );
        assert!(
            held < 64 << 20,
            "{held} bytes held for {} bytes of ops",
            pushes.len()
        );
    }
}

/// The bytes a closure allocates on its own thread, for tests that bound a verifier's memory.
#[cfg(test)]
pub(crate) mod alloc_meter {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static METERED: Cell<bool> = const { Cell::new(false) };
        static HELD: Cell<isize> = const { Cell::new(0) };
        static PEAK: Cell<isize> = const { Cell::new(0) };
    }

    fn count(bytes: isize) {
        let _ = METERED.try_with(|metered| {
            if metered.get() {
                let held = HELD.with(|h| {
                    h.set(h.get() + bytes);
                    h.get()
                });
                PEAK.with(|p| p.set(p.get().max(held)));
            }
        });
    }

    /// The system allocator, counting what the metered thread allocates and frees.
    struct Meter;

    unsafe impl GlobalAlloc for Meter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let p = System.alloc(layout);
            if !p.is_null() {
                count(layout.size() as isize);
            }
            p
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let p = System.alloc_zeroed(layout);
            if !p.is_null() {
                count(layout.size() as isize);
            }
            p
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout);
            count(-(layout.size() as isize));
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let p = System.realloc(ptr, layout, new_size);
            if !p.is_null() {
                count(new_size as isize - layout.size() as isize);
            }
            p
        }
    }

    #[global_allocator]
    static METER: Meter = Meter;

    /// `f`'s result, and the most bytes it held allocated at once on this thread beyond what
    /// was allocated when it started.
    pub(crate) fn peak<T>(f: impl FnOnce() -> T) -> (T, usize) {
        HELD.with(|h| h.set(0));
        PEAK.with(|p| p.set(0));
        METERED.with(|m| m.set(true));
        let result = f();
        METERED.with(|m| m.set(false));
        (result, PEAK.with(|p| p.get()).max(0) as usize)
    }
}
