//! Fund a list of subgroves with a fixed amount of WILL each.
//!
//! Used by `scripts/bring_up_default_subgroves.sh` to give every freshly-
//! registered devnet subgrove enough balance to pay per-submission storage
//! fees so the indexer can actually post updates.
//!
//! Run with:
//!   cargo run --release --example fund_subgroves_batch -- \
//!     --node http://localhost:26657 \
//!     --api  http://localhost:3031 \
//!     --from-did did:willow:validator1 \
//!     --key-hex "$KEY_HEX" \
//!     --will-per-subgrove 100000 \
//!     --subgroves aave-v3-lending,compound-v3-lending,...

use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use willow_sdk::consensus::ConsensusClient;
use willow_sdk::types::FundSubgroveRequest;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "http://localhost:26657")]
    node: String,
    #[arg(long, default_value = "http://localhost:3031")]
    api: String,
    #[arg(long)]
    from_did: String,
    #[arg(long)]
    key_hex: String,
    #[arg(long, default_value = "did:willow:validator1#key-1")]
    public_key_id: String,
    #[arg(long, help = "Whole WILL tokens to fund each subgrove with")]
    will_per_subgrove: u128,
    #[arg(long, help = "Comma-separated list of subgrove_ids to fund")]
    subgroves: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let key_bytes = hex::decode(&args.key_hex).context("decode --key-hex")?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("--key-hex must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&key_array);

    let consensus = ConsensusClient::new_with_api(&args.node, &args.api);

    let amount: u128 = args.will_per_subgrove * 1_000_000_000_000_000_000;
    let subgroves: Vec<String> = args
        .subgroves
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    println!(
        "Funding {} subgrove(s) with {} WILL each ({} base units)",
        subgroves.len(),
        args.will_per_subgrove,
        amount
    );

    let mut failed = 0;
    for subgrove_id in &subgroves {
        let req = FundSubgroveRequest {
            subgrove_id: subgrove_id.clone(),
            amount,
            from_did: args.from_did.clone(),
            signature: Vec::new(),
            public_key_id: args.public_key_id.clone(),
            nonce: 0,
        };
        print!("  funding {} ... ", subgrove_id);
        match consensus.fund_subgrove(req, &signing_key).await {
            Ok(tx_hash) => {
                // broadcast_tx_commit accepted the tx, but FinalizeBlock can
                // still reject it (e.g. "Insufficient balance"). Wait for
                // inclusion then re-query to check tx_result.code.
                let _ = consensus.wait_for_transaction(&tx_hash, 20).await;
                match consensus.get_transaction(&tx_hash).await {
                    Ok(res) if res.code == 0 => {
                        println!("ok ({})", tx_hash);
                    }
                    Ok(res) => {
                        println!("REJECTED at FinalizeBlock: {}", res.log);
                        failed += 1;
                    }
                    Err(e) => {
                        println!("status check failed: {}", e);
                        failed += 1;
                    }
                }
            }
            Err(e) => {
                println!("FAILED at broadcast: {}", e);
                failed += 1;
            }
        }
    }

    if failed > 0 {
        anyhow::bail!("{} of {} fund txs failed", failed, subgroves.len());
    }
    println!("Done.");
    Ok(())
}
