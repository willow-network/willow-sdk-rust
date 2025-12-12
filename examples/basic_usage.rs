//! Basic usage example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Creating a client
//! - Generating and registering a DID
//! - Authenticating
//! - Storing and retrieving data with automatic proof verification
//!
//! Run with: cargo run --example basic_usage

use willow_sdk::{
    auth::generate_did,
    types::SignatureAlgorithm,
    WillowClient,
};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Willow SDK - Basic Usage Example");
    println!("=================================\n");

    // 1. Create client
    println!("1. Creating client...");
    let client = WillowClient::new("http://localhost:3031").await?;
    println!("   Connected to Willow node\n");

    // 2. Generate a DID
    println!("2. Generating Ed25519 DID...");
    let did_info = generate_did(SignatureAlgorithm::Ed25519)?;
    println!("   DID: {}", did_info.did);
    println!("   Public Key ID: {}\n", did_info.public_key_id);

    // 3. Register the DID
    println!("3. Registering DID...");
    client.register_did(&did_info.did_document).await?;
    println!("   DID registered successfully\n");

    // 4. Authenticate
    println!("4. Authenticating...");
    client
        .authenticate(
            &did_info.did,
            &did_info.private_key_hex(),
            &did_info.public_key_id,
        )
        .await?;
    println!("   Authenticated successfully\n");

    // 5. Store data (requires an existing app and dataset)
    // For a complete example, you would first register an app and dataset
    println!("5. Storing data...");
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

    // 6. Retrieve data with automatic proof verification
    println!("\n6. Retrieving data (with proof verification)...");
    match client.data().get("my-app", "users", "alice").await {
        Ok(data) => {
            println!("   Data retrieved and verified:");
            println!("   {}", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 7. Retrieve data without verification (faster)
    println!("\n7. Retrieving data (without verification)...");
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

    // 8. Get root hash
    println!("\n8. Getting root hash...");
    match client.get_root_hash().await {
        Ok(root_hash) => println!("   Verified root hash: {}", root_hash),
        Err(e) => println!("   Note: {}", e),
    }

    println!("\nBasic usage example complete!");
    Ok(())
}
