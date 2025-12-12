//! Token operations example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Getting CAN token information
//! - Checking DID balances
//! - Checking app balances
//! - Getting the fee schedule
//!
//! Run with: cargo run --example token_operations

use willow_sdk::WillowClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Willow SDK - Token Operations Example");
    println!("======================================\n");

    let client = WillowClient::new("http://localhost:3031").await?;

    // 1. Get token info
    println!("1. Getting CAN token info...");
    match client.token().get_info().await {
        Ok(info) => {
            println!("   Name: {}", info.name);
            println!("   Symbol: {}", info.symbol);
            println!("   Decimals: {}", info.decimals);
            println!("   Total Supply: {}", info.total_supply);
            println!("   Minted Supply: {}\n", info.minted_supply);
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 2. Check DID balance
    println!("2. Checking DID balance...");
    let test_did = "did:willow:example123";
    match client.token().get_balance(test_did).await {
        Ok(balance) => {
            println!("   Account: {}", balance.account);
            println!("   Balance: {} CAN", balance.balance);
            println!("   Staked: {} CAN", balance.staked);
            println!("   Unbonding: {} CAN\n", balance.unbonding);
        }
        Err(e) => println!("   Note: {} (DID may not exist)\n", e),
    }

    // 3. Check app balance
    println!("3. Checking app balance...");
    let test_app = "example-app";
    match client.token().get_app_balance(test_app).await {
        Ok(balance) => {
            println!("   Account: {}", balance.account);
            println!("   Balance: {} CAN", balance.balance);
            println!("   Staked: {} CAN", balance.staked);
            println!("   Unbonding: {} CAN\n", balance.unbonding);
        }
        Err(e) => println!("   Note: {} (App may not exist)\n", e),
    }

    // 4. Get fee schedule
    println!("4. Getting fee schedule...");
    match client.token().get_fee_schedule().await {
        Ok(fees) => {
            println!("   Storage fee per byte per day: {} CAN", fees.storage_fee_per_byte_per_day);
            println!("   Query fee: {} CAN", fees.query_fee);
            println!("   Indexing fee per block: {} CAN", fees.indexing_fee_per_block);
            println!("   Minimum app balance: {} CAN\n", fees.minimum_app_balance);
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 5. Economic model summary
    println!("5. Economic model summary...");
    println!("   - Apps are funded with CAN tokens");
    println!("   - Storage fees are automatically deducted");
    println!("   - Query fees apply for verified queries");
    println!("   - Indexers are rewarded for indexing work");
    println!("   - Minimum balances required for operation");

    println!("\nToken operations example complete!");
    Ok(())
}
