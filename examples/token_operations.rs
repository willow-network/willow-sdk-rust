//! Token operations example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Getting WILL token information
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
    println!("1. Getting WILL token info...");
    match client.token().get_info().await {
        Ok(info) => {
            println!("   Name: {}", info.name);
            println!("   Symbol: {}", info.symbol);
            println!("   Decimals: {}", info.decimals);
            println!("   Genesis Supply: {}", info.genesis_supply);
            println!("   Minted Supply: {}", info.minted_supply);
            println!("   Max Supply: {}", info.max_supply);
            println!("   Circulating Supply: {}\n", info.circulating_supply);
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 2. Check DID balance
    println!("2. Checking DID balance...");
    let test_did = "did:willow:example123";
    match client.token().get_balance(test_did).await {
        Ok(balance) => {
            println!("   DID: {}", balance.did);
            println!("   Available: {} WILL", balance.available);
            println!("   Staked: {} WILL", balance.staked);
            println!("   Locked: {} WILL\n", balance.locked);
        }
        Err(e) => println!("   Note: {} (DID may not exist)\n", e),
    }

    // 3. Check subgrove balance
    println!("3. Checking subgrove balance...");
    let test_subgrove = "example-subgrove";
    match client.token().get_subgrove_balance(test_subgrove).await {
        Ok(balance) => {
            println!("   Subgrove: {}", balance.subgrove_id);
            println!("   Balance: {} WILL", balance.balance);
            println!("   Total Spent: {} WILL\n", balance.total_spent);
        }
        Err(e) => println!("   Note: {} (Subgrove may not exist)\n", e),
    }

    // 4. Get fee schedule
    println!("4. Getting fee schedule...");
    match client.token().get_fee_schedule().await {
        Ok(fees) => {
            println!("   DID Registration: {} WILL", fees.did_registration);
            println!(
                "   Subgrove Registration: {} WILL",
                fees.subgrove_registration
            );
            println!(
                "   Subgrove Registration: {} WILL",
                fees.subgrove_registration
            );
            println!("   Base TX Cost: {} wei", fees.base_tx_cost);
            println!("   Cost Per Byte: {} wei", fees.cost_per_byte);
            println!("   Query Fee: {} wei", fees.query_fee);
            println!("   Transfer Fee: {} bps", fees.transfer_fee_percentage);
            println!("   Max TX Size: {} bytes", fees.max_tx_size_bytes);
            println!(
                "   Max Data Payload: {} bytes\n",
                fees.max_data_payload_bytes
            );
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 5. Economic model summary
    println!("5. Economic model summary...");
    println!("   - Subgroves are funded with WILL tokens");
    println!("   - Storage fees are automatically deducted");
    println!("   - Query fees apply for verified queries");
    println!("   - Indexers are rewarded for indexing work");
    println!("   - Minimum balances required for operation");

    println!("\nToken operations example complete!");
    Ok(())
}
