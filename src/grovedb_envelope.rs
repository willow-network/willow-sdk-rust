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

use crate::errors::{Result, WillowError};
use grovedb::operations::proof::{GroveDBProof, LayerProof, ProveOptions};

/// Reject a proof envelope that does not descend `path`, carries layers below
/// it, or sets non-default prove options.
pub fn check_envelope(proof: &[u8], path: &[Vec<u8>]) -> Result<()> {
    let fail = |m: String| WillowError::ProofVerificationFailed(format!("GroveDB envelope: {m}"));
    let config = bincode2::config::standard()
        .with_big_endian()
        .with_no_limit();
    let (envelope, used): (GroveDBProof, usize) =
        bincode2::decode_from_slice(proof, config).map_err(|e| fail(e.to_string()))?;
    if used != proof.len() {
        return Err(fail(format!("{} trailing bytes", proof.len() - used)));
    }
    let GroveDBProof::V0(v0) = envelope;
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

#[cfg(test)]
mod tests {
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

    #[test]
    fn proof_deeper_than_the_path_is_refused() {
        let f = fixture();
        let err = check_envelope(&f.proof, &f.path[..3])
            .unwrap_err()
            .to_string();
        assert!(err.contains("below the query path"), "{err}");
        // The legacy root-level helpers verify at the empty path, so a proof
        // over a real data path is refused there too rather than loosely passed.
        let err = ProofVerifier::verify_item_proof(
            &hex::encode(&f.proof),
            std::str::from_utf8(&f.key).unwrap(),
            &serde_json::Value::Null,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("below the query path"), "{err}");
    }
}
