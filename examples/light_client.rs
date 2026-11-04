//! Light client example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Configuring the light client's validator endpoints
//! - Verifying a value against a header from those endpoints
//! - Exporting and importing trusted state
//!
//! Run with: cargo run --example light_client

use serde_json::json;
use std::time::Duration;
use willow_sdk::{LightClientConfigBuilder, WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Willow SDK - Light Client Example");
    println!("==================================\n");

    // 1. Configure light client with multiple validators
    println!("1. Configuring light client...");
    let light_client_config = LightClientConfigBuilder::new("willow-testnet")
        .validator_endpoints(vec![
            "http://localhost:26657".to_string(), // Node 1
            "http://localhost:26757".to_string(), // Node 2
            "http://localhost:26857".to_string(), // Node 3
        ])
        .trust_threshold(2, 3) // Require 2/3+ validator agreement
        .trusting_period(Duration::from_secs(86400)) // 24 hours
        .max_clock_drift(Duration::from_secs(10))
        .min_validators_for_consensus(2)
        .auto_sync(true)
        .build();

    println!("   Chain ID: willow-testnet");
    println!("   Validators: 3 endpoints configured");
    println!("   Trust threshold: 2/3");
    println!("   Trusting period: 24 hours\n");

    // 2. Create client with light client
    println!("2. Creating client with light client...");
    let client = WillowClient::builder()
        .api_url("http://localhost:3031")
        .consensus_url("http://localhost:26657") // Optional: for consensus operations
        .light_client_config(light_client_config)
        .build()
        .await?;

    // Verify light client is active
    if client.light_client().is_some() {
        println!("   Light client: ACTIVE");
    } else {
        println!("   Light client: Not available");
    }

    // 3. Authenticate with devnet test account
    println!("\n3. Authenticating...");
    client.set_identity(
        DEVNET_VALIDATOR_1.did,
        DEVNET_VALIDATOR_1.private_key,
        DEVNET_VALIDATOR_1.public_key_id,
    );
    println!("   Authenticated as: {}", DEVNET_VALIDATOR_1.did);

    // 4. Retrieve a verified value by key
    // Note: Data must first be stored via consensus transactions
    println!("\n4. Retrieving a verified value...");
    println!("   This checks:");
    println!("   - the GroveDB proof proves this value at its key in the subgrove's data");
    println!("   - its root is the app_hash of the header after the proof's block,");
    println!("     read from the validator endpoints (not from the API)\n");

    match client.data().get("secure-data", "entry-1").await {
        Ok(data) => {
            println!("   Data retrieved and verified:");
            println!("   {}", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 5. Query (a query's documents are returned unverified)
    println!("\n5. Querying (unverified)...");
    let query = json!({ "limit": 10 });

    match client.data().query_unverified("secure-data", query).await {
        Ok(response) => {
            println!(
                "   Query returned {} documents (unverified)",
                response.documents.len()
            );
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 6. Export trusted state for persistence
    println!("\n6. Exporting trusted state...");
    if let Some(lc) = client.light_client() {
        let state = lc.export_trusted_state().await;
        println!("   Exported {} trusted headers", state.headers.len());

        // In production, you would serialize and save this:
        // let json = serde_json::to_string(&state)?;
        // std::fs::write("trusted_state.json", json)?;

        println!("   State can be persisted and restored later");
    }

    // 7. Show verification comparison
    println!("\n7. Verification comparison...");
    println!("\n   VERIFIED READS (data().get):");
    println!("   + The proof binds the value at its key in the subgrove's data");
    println!("   + Its root is checked against a header from the validator endpoints");
    println!("   - Headers are trusted as those endpoints serve them; commit");
    println!("     signatures are not checked\n");

    println!("   UNVERIFIED (performance mode):");
    println!("   + Fastest response times");
    println!("   - Trusts the node completely");
    println!("   - Only use with trusted nodes");

    println!("\nLight client example complete!");
    Ok(())
}
