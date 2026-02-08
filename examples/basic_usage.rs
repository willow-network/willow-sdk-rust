//! Basic usage example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Creating a client
//! - Authenticating with the pre-registered devnet test account
//! - Storing and retrieving data with automatic proof verification
//!
//! Run with: cargo run --example basic_usage

use serde_json::json;
use willow_sdk::{WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Willow SDK - Basic Usage Example");
    println!("=================================\n");

    // 1. Create client
    println!("1. Creating client...");
    let client = WillowClient::new("http://localhost:3031").await?;
    println!("   Connected to Willow node\n");

    // 2. Authenticate with devnet test account
    println!("2. Authenticating with devnet test account...");
    println!("   DID: {}", DEVNET_VALIDATOR_1.did);
    client
        .authenticate(
            DEVNET_VALIDATOR_1.did,
            DEVNET_VALIDATOR_1.private_key,
            DEVNET_VALIDATOR_1.public_key_id,
        )
        .await?;
    println!("   Authenticated successfully\n");

    // 3. Store data (requires an existing app and dataset)
    // For a complete example, you would first register an app and dataset
    println!("3. Storing data...");
    let test_data = json!({
        "name": "Alice",
        "score": 100,
        "active": true
    });

    match client
        .data()
        .store_item("my-app", "users", "alice", test_data.clone())
        .await
    {
        Ok(_) => println!("   Data stored successfully"),
        Err(e) => println!("   Note: {}", e),
    }

    // 4. Retrieve data with automatic proof verification
    println!("\n4. Retrieving data (with proof verification)...");
    match client.data().get("my-app", "users", "alice").await {
        Ok(data) => {
            println!("   Data retrieved and verified:");
            println!("   {}", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 5. Retrieve data without verification (faster)
    println!("\n5. Retrieving data (without verification)...");
    match client
        .data()
        .get_unverified("my-app", "users", "alice")
        .await
    {
        Ok(data) => {
            println!("   Data retrieved (unverified):");
            println!("   {}", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 6. Get root hash
    println!("\n6. Getting root hash...");
    match client.get_root_hash().await {
        Ok(root_hash) => println!("   Verified root hash: {}", root_hash),
        Err(e) => println!("   Note: {}", e),
    }

    println!("\nBasic usage example complete!");
    Ok(())
}
