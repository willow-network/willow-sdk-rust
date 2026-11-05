//! Light client example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Configuring the light client's validator endpoints
//! - Verifying a value against a header from those endpoints
//! - Exporting the headers the light client holds
//!
//! Run with: cargo run --example light_client

use serde_json::json;
use willow_sdk::{LightClientConfigBuilder, WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Willow SDK - Light Client Example");
    println!("==================================\n");

    // 1. Configure the consensus nodes verified reads take headers from. The SDK trusts them:
    // it takes each header from the first that serves it and doesn't verify validator
    // signatures, so list only nodes you trust. Every verified read needs
    // `min_validators_for_consensus` of them to report the chain's latest height.
    println!("1. Configuring light client...");
    let light_client_config = LightClientConfigBuilder::new("willow-testnet")
        .validator_endpoints(vec!["http://localhost:26657".to_string()])
        .min_validators_for_consensus(1)
        .max_proof_lag_blocks(20)
        .build();

    println!("   Chain ID: willow-testnet");
    println!("   Endpoints: 1, trusted as it serves headers (no signature check)\n");

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

    // 6. Export the headers the light client holds, for persistence
    println!("\n6. Exporting the light client's headers...");
    if let Some(lc) = client.light_client() {
        let state = lc.export_trusted_state().await;
        println!("   Exported {} headers", state.headers.len());

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
