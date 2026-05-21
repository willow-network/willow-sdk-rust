//! Register a subgrove from a canonical manifest JSON file.
//!
//! Chain-family-agnostic: the same tool covers EVM and Solana
//! subgroves. `WillowManifest.data_sources` dispatches by each entry's
//! `network` field (`mainnet`, `bsc`, `solana-mainnet`, …), so a single
//! registrar handles every supported chain without a per-family CLI.
//!
//! Run with:
//!   cargo run --release --example register_subgrove_from_manifest -- \
//!     --node http://localhost:26657 \
//!     --api  http://localhost:3031 \
//!     --subgrove-id my-subgrove \
//!     --description "Short human-readable summary" \
//!     --manifest    ./my-subgrove.manifest.json \
//!     --schema-file ./my-subgrove.graphql \
//!     --execution-mode IndexerExecution \
//!     --sampling-rate-percent 5 \
//!     --fund-will 10000 \
//!     --replace-existing
//!
//! The manifest JSON must be a valid `WillowManifest`. For an EVM
//! source: `{name, network, address, abi, start_block, events}`. For a
//! Solana source: `{name, network: "solana-mainnet", program_id,
//! start_slot, instructions}`. See
//! `crates/types/src/consensus/manifest.rs` for the canonical schema.
//!
//! For GkrExecution subgroves bound to a circuit template (e.g.
//! `balance-aggregator-v2`), pass `--template-config-file ./tc.json`
//! pointing at a JSON `TemplateSubgroveConfig`. Without it,
//! GkrExecution subgroves register without a template binding and
//! consensus computes the wrong expected starting state at chain-tip
//! submission time.

use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use willow_sdk::consensus::ConsensusClient;
use willow_sdk::subgrove_config::{IndexerConfigDef, SubgroveDefinition};
use willow_sdk::types::{DeregisterSubgroveRequest, FundSubgroveRequest};
use willow_types::consensus::WillowManifest;
use willow_types::storage::TemplateSubgroveConfig;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "http://localhost:26657")]
    node: String,
    #[arg(long, default_value = "http://localhost:3031")]
    api: String,
    #[arg(long, default_value = "did:willow:validator1")]
    owner_did: String,
    // Default key_hex is the RFC 8032 §7.1 Test 1 Ed25519 vector — the
    // pre-funded devnet DID. Pass a real key for any non-devnet target.
    #[arg(
        long,
        default_value = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )]
    key_hex: String,
    #[arg(long)]
    subgrove_id: String,
    #[arg(long)]
    description: String,
    #[arg(long, help = "Path to a JSON file containing a canonical WillowManifest")]
    manifest: String,
    #[arg(long, help = "Path to a GraphQL schema file (.graphql)")]
    schema_file: String,
    #[arg(long, default_value = "IndexerExecution")]
    execution_mode: String,
    #[arg(long, default_value_t = 5)]
    sampling_rate_percent: u8,
    #[arg(long, default_value_t = 1)]
    min_indexers: u8,
    #[arg(long, default_value_t = 3)]
    max_indexers: u8,
    #[arg(
        long,
        default_value_t = 0,
        help = "WILL tokens to fund the subgrove with after registering (0 = skip)."
    )]
    fund_will: u64,
    #[arg(
        long,
        help = "Deregister any existing subgrove with this id before registering."
    )]
    replace_existing: bool,
    #[arg(
        long,
        help = "Path to a JSON file containing a TemplateSubgroveConfig. Required for GkrExecution subgroves bound to a circuit template; otherwise omit."
    )]
    template_config_file: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let manifest_str = std::fs::read_to_string(&args.manifest)
        .with_context(|| format!("read manifest {}", args.manifest))?;
    let manifest: WillowManifest = serde_json::from_str(&manifest_str)
        .with_context(|| format!("parse manifest {} as WillowManifest", args.manifest))?;
    manifest
        .validate()
        .map_err(|e| anyhow::anyhow!("manifest validation failed: {}", e))?;

    let schema = std::fs::read_to_string(&args.schema_file)
        .with_context(|| format!("read schema {}", args.schema_file))?;

    let template_config: Option<TemplateSubgroveConfig> = match &args.template_config_file {
        Some(path) => {
            let tc_str = std::fs::read_to_string(path)
                .with_context(|| format!("read template-config {}", path))?;
            let tc: TemplateSubgroveConfig = serde_json::from_str(&tc_str)
                .with_context(|| format!("parse template-config {} as TemplateSubgroveConfig", path))?;
            Some(tc)
        }
        None => None,
    };

    let key_bytes = hex::decode(&args.key_hex).context("decode --key-hex")?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("--key-hex must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&key_array);

    let consensus = ConsensusClient::new_with_api(&args.node, &args.api);
    let public_key_id = format!("{}#key-1", args.owner_did);

    if args.replace_existing {
        let dereg = DeregisterSubgroveRequest {
            subgrove_id: args.subgrove_id.clone(),
            owner_did: args.owner_did.clone(),
            signature: Vec::new(),
            public_key_id: public_key_id.clone(),
            nonce: 0,
        };
        match consensus.deregister_subgrove(dereg, &signing_key).await {
            Ok(tx) => {
                println!("Deregistered. tx_hash = {}", tx);
                let _ = consensus.wait_for_transaction(&tx, 20).await?;
            }
            Err(e) => {
                println!("Deregister failed (subgrove may not exist, continuing): {}", e);
            }
        }
    }

    let definition = SubgroveDefinition {
        subgrove_id: args.subgrove_id.clone(),
        description: args.description.clone(),
        execution_mode: args.execution_mode.clone(),
        sampling_rate_percent: Some(args.sampling_rate_percent),
        required_tee: None,
        indexer_config: IndexerConfigDef {
            min_indexers: args.min_indexers,
            max_indexers: args.max_indexers,
            ..IndexerConfigDef::default()
        },
        schema,
        manifest,
        template_config,
    };

    println!("Registering subgrove '{}' on {}", args.subgrove_id, args.node);
    let reg_tx = consensus
        .register_blockchain_subgrove(&definition, &args.owner_did, &public_key_id, &signing_key, None)
        .await
        .context("register_blockchain_subgrove failed")?;
    println!("Registered. tx_hash = {}", reg_tx);
    let _ = consensus.wait_for_transaction(&reg_tx, 20).await?;

    if args.fund_will > 0 {
        let amount: u128 = (args.fund_will as u128) * 1_000_000_000_000_000_000;
        let req = FundSubgroveRequest {
            subgrove_id: args.subgrove_id.clone(),
            amount,
            from_did: args.owner_did.clone(),
            signature: Vec::new(),
            public_key_id: public_key_id.clone(),
            nonce: 0,
        };
        println!("Funding with {} WILL...", args.fund_will);
        let fund_tx = consensus.fund_subgrove(req, &signing_key).await?;
        println!("Funded. tx_hash = {}", fund_tx);
        let _ = consensus.wait_for_transaction(&fund_tx, 20).await?;
    }

    Ok(())
}
