//! Rotate the signing key on an existing Willow DID.
//!
//! Submits an `UpdateDid` transaction signed by the *current* on-chain key,
//! replacing the DID document's key with one whose private half is written to
//! disk first. After the tx commits, only the new key can sign as this DID.
//!
//! The replacement document is derived from the live on-chain document, so the
//! DID's id, service endpoints, and `created` timestamp survive the rotation.
//!
//! Nothing is broadcast without `--broadcast`. The default is a dry run that
//! prints the replacement document, the exact bytes that would be signed, and
//! the resolved nonce, then stops.
//!
//! The one unrecoverable mistake is a replacement document whose
//! `authentication` set names a key nobody holds: the DID can never sign again.
//! Before broadcasting, this tool signs a probe with the new private key and
//! verifies it against the document's public key, and refuses to continue if
//! they disagree.
//!
//! Step 1 — rehearse (writes the new key, submits nothing):
//!   cargo run --release --example rotate_did -- \
//!     --api http://localhost:3031 \
//!     --node http://localhost:26657 \
//!     --did did:willow:validator1 \
//!     --current-key-file ~/.willow/keys/validator1.key \
//!     --current-key-id did:willow:validator1#key-1 \
//!     --new-key-out ~/.willow/keys/validator1.new.key
//!
//! Step 2 — read the printed document and message, then submit with the key
//! step 1 wrote:
//!   cargo run --release --example rotate_did -- \
//!     ... --new-key-in ~/.willow/keys/validator1.new.key --broadcast

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use willow_sdk::consensus::ConsensusClient;
use willow_sdk::did_rotation::{
    assert_key_controls_document, ed25519_public_key_hex, parse_ed25519_seed, read_key_file,
    rotated_document, update_did_signing_message, write_new_key_file,
};
use willow_sdk::types::{DidDocument, SignatureAlgorithm};

#[derive(Parser, Debug)]
#[command(about = "Rotate the signing key on a Willow DID (dry run unless --broadcast)")]
struct Args {
    /// Validator API URL. Used to read the current DID document and the nonce.
    #[arg(long, default_value = "http://localhost:3031")]
    api: String,

    /// CometBFT RPC URL (used to broadcast the tx and as the read fallback).
    #[arg(long, default_value = "http://localhost:26657")]
    node: String,

    /// DID being rotated, e.g. `did:willow:validator1`.
    #[arg(long)]
    did: String,

    /// Hex-encoded current private key. Prefer `--current-key-file`: an
    /// argument is visible in `ps` and shell history.
    #[arg(long, conflicts_with = "current_key_file")]
    current_key_hex: Option<String>,

    /// File holding the hex-encoded current private key.
    #[arg(long)]
    current_key_file: Option<PathBuf>,

    /// Public key ID for the current key, e.g. `did:willow:validator1#key-1`.
    #[arg(long)]
    current_key_id: String,

    /// Public key ID to use for the new key. Defaults to `--current-key-id`,
    /// which keeps the replacement document drop-in compatible with anything
    /// that already references that id (other SDKs, scripts, etc.).
    #[arg(long)]
    new_key_id: Option<String>,

    /// Path to write the new hex private key to. Refuses to overwrite an
    /// existing file. Written before any network call.
    #[arg(long, conflicts_with = "new_key_in")]
    new_key_out: Option<PathBuf>,

    /// Hex-encoded new private key, instead of generating one. Requires
    /// `--new-key-out` to persist it.
    #[arg(long, requires = "new_key_out")]
    new_key_hex: Option<String>,

    /// Reuse the key a previous dry run already wrote, so the run that
    /// broadcasts signs the document the dry run showed you.
    #[arg(long)]
    new_key_in: Option<PathBuf>,

    /// Actually submit the transaction. Without this the tool prints what it
    /// would do and exits.
    #[arg(long)]
    broadcast: bool,

    /// Print the plan and exit. This is the default; the flag exists so a
    /// script can say so out loud.
    #[arg(long, conflicts_with = "broadcast")]
    dry_run: bool,

    /// How many 2-second polls to wait for the tx to land in a block.
    #[arg(long, default_value_t = 30)]
    confirm_attempts: u32,

    /// Signature algorithm for the current key. Only ed25519 is supported.
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

    let current_key_hex = load_current_key(&args)?;
    let new_key_id = args
        .new_key_id
        .clone()
        .unwrap_or_else(|| args.current_key_id.clone());

    // 1. Settle the new key and get it onto disk before anything else. A
    //    rotation whose new key was never persisted is the same as a brick.
    let (new_private_key_hex, key_path) = resolve_new_key(&args)?;
    let new_public_key_hex = hex::encode(
        parse_ed25519_seed(&new_private_key_hex)
            .context("new private key")?
            .verifying_key()
            .as_bytes(),
    );
    println!("New private key: {}", key_path.display());
    println!("New public key:  {}", new_public_key_hex);

    // 2. Derive the replacement from the live document — never invent one.
    let client = ConsensusClient::new_with_api(&args.node, &args.api);
    let current_doc = client
        .get_did_document(&args.did)
        .await
        .with_context(|| format!("read the current DID document for {}", args.did))?;
    check_current_document(&current_doc, &args)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let new_doc = rotated_document(&current_doc, &new_key_id, &new_public_key_hex, now);

    // 3. The anti-brick gate. Everything above is reversible; past this point
    //    a wrong authentication set is not.
    run_anti_brick_gate(&new_doc, &new_key_id, &new_private_key_hex)?;

    // 4. Resolve the nonce once, and sign exactly the message we print.
    let nonce = client
        .get_next_nonce(&args.did)
        .await
        .context("resolve the next nonce")?;
    let message = update_did_signing_message(&new_doc, nonce)?;

    println!();
    println!("Replacement DID document:");
    println!("{}", serde_json::to_string_pretty(&new_doc)?);
    println!();
    println!("Nonce: {}", nonce);
    println!("Signing message (exactly the bytes the chain verifies):");
    println!("{}", message);
    println!();

    if args.dry_run || !args.broadcast {
        println!("DRY RUN — nothing was submitted.");
        if args.new_key_in.is_some() {
            println!("Re-run with --broadcast to sign this document with the current key.");
        } else {
            println!(
                "Re-run with --new-key-in {} --broadcast to sign this document with the current key.",
                key_path.display()
            );
        }
        return Ok(());
    }

    // 5. Broadcast.
    println!(
        "Broadcasting UpdateDid signed by {}...",
        args.current_key_id
    );
    let tx_hash = client
        .update_did_with_nonce(
            &new_doc,
            &current_key_hex,
            &args.current_key_id,
            args.algorithm.clone().into(),
            nonce,
        )
        .await
        .context("UpdateDid tx submission failed")?;
    println!("CheckTx accepted, tx hash {}", tx_hash);

    let outcome = client
        .wait_for_tx_outcome(&tx_hash, args.confirm_attempts)
        .await
        .context("poll for tx inclusion")?;
    let Some(outcome) = outcome else {
        bail!(
            "tx {} was accepted into the mempool but was not in a block after {} polls — \
             the rotation may still land; re-read {}/did/{} before doing anything else",
            tx_hash,
            args.confirm_attempts,
            args.api.trim_end_matches('/'),
            args.did
        );
    };
    println!(
        "Included at height {} with code {}{}",
        outcome.height,
        outcome.code,
        if outcome.log.is_empty() {
            String::new()
        } else {
            format!(" — {}", outcome.log)
        }
    );
    if outcome.code != 0 {
        bail!(
            "UpdateDid failed on chain (code {}): {}. The DID was NOT rotated; the current key \
             still works.",
            outcome.code,
            outcome.log
        );
    }

    // 6. Confirm against chain state, not against the tx result.
    let live_doc = client
        .get_did_document(&args.did)
        .await
        .context("re-read the DID document after rotation")?;
    confirm_rotation(&live_doc, &new_key_id, &new_public_key_hex, &current_doc)?;

    println!();
    println!(
        "Rotation confirmed: {} now authenticates only with {} ({}). The old key is dead on chain.",
        args.did, new_key_id, new_public_key_hex
    );
    println!(
        "Persist {} off-box now — it is the only key that can administer this DID.",
        key_path.display()
    );
    Ok(())
}

fn load_current_key(args: &Args) -> Result<String> {
    match (&args.current_key_hex, &args.current_key_file) {
        (Some(hex_value), None) => Ok(hex_value.trim().to_string()),
        (None, Some(path)) => {
            read_key_file(path).with_context(|| format!("read current key {}", path.display()))
        }
        _ => bail!("pass exactly one of --current-key-hex or --current-key-file"),
    }
}

/// Generate or accept the new key and write it out, or reuse one a previous dry
/// run already wrote. Returns the hex key and the file that holds it.
fn resolve_new_key(args: &Args) -> Result<(String, PathBuf)> {
    match (&args.new_key_out, &args.new_key_in) {
        (Some(path), None) => {
            let private_key_hex = match &args.new_key_hex {
                Some(supplied) => {
                    let normalized = supplied.trim().to_string();
                    parse_ed25519_seed(&normalized).context("--new-key-hex")?;
                    normalized
                }
                None => {
                    let mut seed = [0u8; 32];
                    OsRng.fill_bytes(&mut seed);
                    hex::encode(SigningKey::from_bytes(&seed).to_bytes())
                }
            };
            write_new_key_file(path, &private_key_hex)
                .with_context(|| format!("write new key to {}", path.display()))?;
            Ok((private_key_hex, path.clone()))
        }
        (None, Some(path)) => {
            let private_key_hex = read_key_file(path)
                .with_context(|| format!("read new key from {}", path.display()))?;
            Ok((private_key_hex, path.clone()))
        }
        _ => bail!("pass exactly one of --new-key-out or --new-key-in"),
    }
}

/// Fail before the network sees anything if the current document cannot
/// authorize this rotation, and say out loud what the replacement will carry.
fn check_current_document(current: &DidDocument, args: &Args) -> Result<()> {
    if current.id != args.did {
        bail!(
            "chain returned a document for {:?} when asked for {:?}",
            current.id,
            args.did
        );
    }
    if !current.authentication.contains(&args.current_key_id) {
        bail!(
            "{} is not in the on-chain authentication set {:?} — it cannot authorize this update",
            args.current_key_id,
            current.authentication
        );
    }
    if !current.service.is_empty() {
        println!(
            "Carrying {} service endpoint(s) across unchanged.",
            current.service.len()
        );
    }
    if current.proof.is_some() {
        println!(
            "Note: the current document carries a proof bound to the outgoing key; \
             the replacement drops it."
        );
    }
    Ok(())
}

/// Prove the document about to be broadcast is signable by the key on disk.
fn run_anti_brick_gate(
    new_doc: &DidDocument,
    new_key_id: &str,
    new_private_key_hex: &str,
) -> Result<()> {
    let matched = assert_key_controls_document(new_doc, new_private_key_hex)
        .map_err(|e| anyhow::anyhow!("ANTI-BRICK GATE FAILED — nothing was submitted. {}", e))?;

    if new_doc.authentication != vec![new_key_id.to_string()] {
        bail!(
            "ANTI-BRICK GATE FAILED — nothing was submitted. Replacement authentication set is \
             {:?}, expected exactly [{:?}]",
            new_doc.authentication,
            new_key_id
        );
    }
    println!(
        "Anti-brick gate passed: {} signs for the replacement document.",
        matched
    );
    Ok(())
}

/// Confirm chain state, not the tx receipt: the new key is live and the old one
/// is gone.
fn confirm_rotation(
    live: &DidDocument,
    new_key_id: &str,
    new_public_key_hex: &str,
    previous: &DidDocument,
) -> Result<()> {
    if live.authentication != vec![new_key_id.to_string()] {
        bail!(
            "post-rotation check FAILED: on-chain authentication set is {:?}, expected [{:?}]",
            live.authentication,
            new_key_id
        );
    }
    let live_keys: Vec<String> = live
        .public_keys
        .iter()
        .filter_map(ed25519_public_key_hex)
        .collect();
    if live_keys != vec![new_public_key_hex.to_string()] {
        bail!(
            "post-rotation check FAILED: on-chain public keys are {:?}, expected [{:?}]",
            live_keys,
            new_public_key_hex
        );
    }
    for old_key in previous
        .public_keys
        .iter()
        .filter_map(ed25519_public_key_hex)
    {
        if old_key != new_public_key_hex && live_keys.contains(&old_key) {
            bail!(
                "post-rotation check FAILED: retired key {} is still on chain",
                old_key
            );
        }
    }
    Ok(())
}
