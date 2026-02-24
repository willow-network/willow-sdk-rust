//! Check Balances Example
//!
//! Checks token balances for a DID or app.
//!
//! Run with: cargo run --example check_balances
//!
//! Prerequisites:
//! - Local Willow network running (./scripts/start_network.sh)

use willow_sdk::{WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // CONFIGURATION - Modify these values for your testing
    // =========================================================================
    let api_url = "http://localhost:3031";

    // DID to check balance for
    let did = DEVNET_VALIDATOR_1.did;
    let private_key = DEVNET_VALIDATOR_1.private_key;
    let public_key_id = DEVNET_VALIDATOR_1.public_key_id;

    // Optional: App to check balance for
    let app_id = Some("my-app");
    // =========================================================================

    let client = WillowClient::new(api_url).await?;

    client.set_identity(did, private_key, public_key_id);

    // Check DID balance
    println!("DID: {}", did);
    match client.token().get_balance(did).await {
        Ok(balance) => {
            println!("  Available: {} WILL", balance.available);
            if balance.staked > 0 {
                println!("  Staked: {} WILL", balance.staked);
            }
            if balance.locked > 0 {
                println!("  Locked: {} WILL", balance.locked);
            }
        }
        Err(e) => println!("  Error: {}", e),
    }

    // Check app balance if specified
    if let Some(app) = app_id {
        println!("\nApp: {}", app);
        match client.token().get_app_balance(app).await {
            Ok(balance) => {
                println!("  Balance: {} WILL", balance.balance);
            }
            Err(e) => println!("  Error: {}", e),
        }
    }

    // Show fee schedule
    println!("\nFee Schedule:");
    match client.token().get_fee_schedule().await {
        Ok(fees) => {
            println!("  DID Registration: {} WILL", fees.did_registration);
            println!("  App Registration: {} WILL", fees.app_registration);
            println!("  Subgrove Registration: {} WILL", fees.subgrove_registration);
            println!("  Data Write: {} WILL/KB", fees.data_write_per_kb);
            println!("  Proof Generation: {} WILL", fees.proof_generation);
            println!("  Query (after limit): {} WILL", fees.query_after_limit);
            println!(
                "  Transfer Fee: {} bps",
                fees.transfer_fee_percentage
            );
        }
        Err(e) => println!("  Error: {}", e),
    }

    Ok(())
}
