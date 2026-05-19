//! Register a Solana subgrove against a running Willow node.
//!
//! Targets Marinade Finance's mSOL staking program by default, indexing
//! the `deposit` and `liquid_unstake` Anchor instructions.
//!
//! Run with:
//!   cargo run --release --example register_solana_subgrove -- \
//!     --node http://localhost:26657 \
//!     --api  http://localhost:3031

use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use willow_sdk::consensus::ConsensusClient;
use willow_sdk::subgrove_config::{IndexerConfigDef, SubgroveDefinition};
use willow_types::consensus::{
    DataSource, InstructionDiscriminator, SolanaDataSource, SolanaPubkey, SupportedChain,
    WillowManifest,
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "http://localhost:26657")]
    node: String,
    #[arg(long, default_value = "http://localhost:3031")]
    api: String,
    #[arg(long, default_value = "did:willow:validator1")]
    owner_did: String,
    // Default key_hex is the RFC 8032 §7.1 Test 1 Ed25519 vector.
    #[arg(
        long,
        default_value = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )]
    key_hex: String,
    #[arg(long, default_value = "jupiter-v6-swaps")]
    subgrove_id: String,
    #[arg(long, default_value = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4")]
    program_id: String,
    #[arg(
        long,
        default_value = "0xc1209b3341d69c81,0xe517cb977ae3ad2a",
        help = "Comma-separated 8-byte instruction discriminators (0x...). Defaults to Jupiter v6 shared_accounts_route + route."
    )]
    instructions: String,
    #[arg(long, default_value = "MainProgram")]
    data_source_name: String,
    #[arg(
        long,
        default_value = "Jupiter v6 aggregator — shared_accounts_route + route swaps"
    )]
    description: String,
    #[arg(
        long,
        default_value_t = 0,
        help = "Slot to start indexing from. 0 = fetch current tip from --solana-rpc."
    )]
    start_slot: u64,
    #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
    solana_rpc: String,
    #[arg(
        long,
        default_value_t = 0,
        help = "WILL tokens to fund the subgrove with after registering (0 = skip). Subgroves need balance to pay per-submission storage fees."
    )]
    fund_will: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let start_slot = if args.start_slot == 0 {
        let client = reqwest::Client::new();
        let resp: serde_json::Value = client
            .post(&args.solana_rpc)
            .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getSlot"}))
            .send()
            .await
            .context("getSlot request failed")?
            .json()
            .await
            .context("getSlot response parse failed")?;
        let tip = resp["result"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("getSlot returned non-u64: {}", resp))?;
        println!(
            "Fetched current Solana tip: {} (will start indexing from here)",
            tip
        );
        tip
    } else {
        args.start_slot
    };

    let program_id =
        SolanaPubkey::parse(&args.program_id).map_err(|e| anyhow::anyhow!("program_id: {}", e))?;
    let instructions = args
        .instructions
        .split(',')
        .map(|s| InstructionDiscriminator::parse(s.trim()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("instructions: {}", e))?;

    let manifest = WillowManifest {
        spec_version: "1.0.0".to_string(),
        description: Some(args.description.clone()),
        data_sources: vec![DataSource::Solana(SolanaDataSource {
            name: args.data_source_name.clone(),
            network: SupportedChain::SolanaMainnet,
            program_id,
            start_slot,
            instructions,
        })],
    };
    manifest
        .validate()
        .map_err(|e| anyhow::anyhow!("manifest validation failed: {}", e))?;

    let definition = SubgroveDefinition {
        subgrove_id: args.subgrove_id.clone(),
        description: args.description.clone(),
        execution_mode: "IndexerExecution".to_string(),
        sampling_rate_percent: Some(5),
        required_tee: None,
        indexer_config: IndexerConfigDef::default(),
        schema:
            "type Instruction @entity {\n  id: ID!\n  slot: BigInt!\n  discriminator: String!\n}\n"
                .to_string(),
        manifest,
        template_config: None,
    };

    let key_bytes = hex::decode(&args.key_hex).context("decode --key-hex")?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("--key-hex must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&key_array);

    let consensus = ConsensusClient::new_with_api(&args.node, &args.api);
    let public_key_id = format!("{}#key-1", args.owner_did);

    println!(
        "Registering Solana subgrove '{}' on {} (program {}, start_slot {})",
        args.subgrove_id, args.node, args.program_id, start_slot
    );

    let tx_hash = consensus
        .register_blockchain_subgrove(
            &definition,
            &args.owner_did,
            &public_key_id,
            &signing_key,
            None,
        )
        .await
        .context("register_blockchain_subgrove failed")?;

    println!("Submitted. tx_hash = {}", tx_hash);

    if args.fund_will > 0 {
        let amount: u128 = (args.fund_will as u128) * 1_000_000_000_000_000_000;
        let fund_request = willow_sdk::types::FundSubgroveRequest {
            subgrove_id: args.subgrove_id.clone(),
            amount,
            from_did: args.owner_did.clone(),
            signature: Vec::new(),
            public_key_id: public_key_id.clone(),
            nonce: 0,
        };
        println!(
            "Funding subgrove with {} WILL ({} base units)…",
            args.fund_will, amount
        );
        let fund_tx = consensus
            .fund_subgrove(fund_request, &signing_key)
            .await
            .context("fund_subgrove failed")?;
        println!("Funded. tx_hash = {}", fund_tx);
    }

    println!(
        "Verify with: curl -s {}/subgroves | jq '.data[] | select(.subgrove_id == \"{}\")'",
        args.api, args.subgrove_id
    );
    Ok(())
}
