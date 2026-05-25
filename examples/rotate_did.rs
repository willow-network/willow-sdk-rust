//! Rotate the signing key on an existing Willow DID.
//!
//! Submits an UpdateDidTx signed by the *current* on-chain key, swapping the
//! on-chain DID document to a freshly-generated keypair. After the tx commits,
//! only the new key can sign as this DID.
//!
//! The new private key is written to `--new-key-out` *before* the tx is
//! submitted — there is no way to recover it after rotation, so this file
//! must exist in your secure store the moment the tx lands.
//!
//! Run with:
//!   cargo run --release --example rotate_did -- \
//!     --api http://localhost:3031 \
//!     --node http://localhost:26657 \
//!     --did did:willow:validator1 \
//!     --current-key-hex 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60 \
//!     --current-key-id did:willow:validator1#key-1 \
//!     --new-key-out /tmp/validator1.new.priv

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use willow_sdk::consensus::ConsensusClient;
use willow_sdk::types::{DidDocument, PublicKey, SignatureAlgorithm};

#[derive(Parser, Debug)]
struct Args {
    /// Validator API URL. The SDK auto-fetches the next nonce from this.
    #[arg(long, default_value = "http://localhost:3031")]
    api: String,

    /// CometBFT RPC URL (used to broadcast the tx).
    #[arg(long, default_value = "http://localhost:26657")]
    node: String,

    /// DID being rotated, e.g. `did:willow:validator1`.
    #[arg(long)]
    did: String,

    /// Hex-encoded current private key (the one already authorized on chain).
    #[arg(long)]
    current_key_hex: String,

    /// Public key ID for the current key, e.g. `did:willow:validator1#key-1`.
    #[arg(long)]
    current_key_id: String,

    /// Public key ID to use for the new key. Defaults to `--current-key-id`,
    /// which keeps the replacement document drop-in compatible with anything
    /// that already references that id (other SDKs, scripts, etc.).
    #[arg(long)]
    new_key_id: Option<String>,

    /// Path to write the freshly-generated hex private key to. Required —
    /// losing this file after rotation is unrecoverable.
    #[arg(long)]
    new_key_out: PathBuf,

    /// Signature algorithm. Currently only ed25519 is supported.
    #[arg(long, value_enum, default_value = "ed25519")]
    algorithm: AlgorithmArg,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum AlgorithmArg {
    Ed25519,
}

impl From<AlgorithmArg> for SignatureAlgorithm {
    fn from(arg: AlgorithmArg) -> Self {
        match arg {
            AlgorithmArg::Ed25519 => SignatureAlgorithm::Ed25519,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let new_key_id = args
        .new_key_id
        .unwrap_or_else(|| args.current_key_id.clone());

    // 1. Generate a fresh keypair. Write the private key out *first* so a
    //    later failure can't lose it.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let new_priv_hex = hex::encode(signing_key.to_bytes());
    let new_pub_hex = hex::encode(verifying_key.as_bytes());

    std::fs::write(&args.new_key_out, &new_priv_hex)
        .with_context(|| format!("write new private key to {}", args.new_key_out.display()))?;
    // Best-effort 0600 on Unix. Failure here isn't fatal — the file exists,
    // which is what matters.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&args.new_key_out, std::fs::Permissions::from_mode(0o600));
    }
    println!("New private key written to {}", args.new_key_out.display());
    println!("New public key: {}", new_pub_hex);

    // 2. Build the replacement DID document — same id, new keys.
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let new_doc = DidDocument {
        id: args.did.clone(),
        public_keys: vec![PublicKey {
            id: new_key_id.clone(),
            key_type: "Ed25519VerificationKey2018".to_string(),
            controller: args.did.clone(),
            public_key_hex: Some(new_pub_hex.clone()),
            public_key_base58: None,
        }],
        authentication: vec![new_key_id.clone()],
        service: vec![],
        created: now,
        updated: now,
        proof: None,
    };

    // 3. Submit, signing with the *current* (about-to-be-replaced) key.
    let client = ConsensusClient::new_with_api(&args.node, &args.api);
    let tx_hash = client
        .update_did(
            &new_doc,
            &args.current_key_hex,
            &args.current_key_id,
            args.algorithm.into(),
        )
        .await
        .context("UpdateDid tx submission failed")?;

    println!("Rotation tx submitted: {}", tx_hash);
    println!();
    println!("Verify after the next block:");
    println!(
        "  curl {}/did/{} | jq '.public_keys[].public_key_hex'",
        args.api.trim_end_matches('/'),
        args.did
    );
    println!("    → expect: \"{}\"", new_pub_hex);
    println!();
    println!(
        "Then prove the rotation took effect by signing a throwaway tx with \
         the new key (read from {}) and confirming it succeeds; do the same \
         with the old key and confirm it fails.",
        args.new_key_out.display()
    );
    Ok(())
}
