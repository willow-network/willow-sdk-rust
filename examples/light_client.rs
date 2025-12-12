//! Light client example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Configuring a light client for trustless verification
//! - Verifying data against multiple validators
//! - Exporting and importing trusted state
//!
//! Run with: cargo run --example light_client

use willow_sdk::{
    auth::generate_did,
    types::SignatureAlgorithm,
    WillowClient, LightClientConfigBuilder,
};
use serde_json::json;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Willow SDK - Light Client Example");
    println!("==================================\n");

    // 1. Configure light client with multiple validators
    println!("1. Configuring light client...");
    let light_client_config = LightClientConfigBuilder::new("willow-testnet")
        .validator_endpoints(vec![
            "http://localhost:26657".to_string(),
            "http://localhost:26757".to_string(),
            "http://localhost:26857".to_string(),
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
        .light_client_config(light_client_config)
        .build()
        .await?;

    // Verify light client is active
    if client.light_client().is_some() {
        println!("   Light client: ACTIVE");
    } else {
        println!("   Light client: Not available");
    }

    // 3. Authenticate
    println!("\n3. Authenticating...");
    let did_info = generate_did(SignatureAlgorithm::Ed25519)?;
    client.register_did(&did_info.did_document).await?;
    client
        .authenticate(
            &did_info.did,
            &did_info.private_key_hex(),
            &did_info.public_key_id,
        )
        .await?;
    println!("   Authenticated as: {}", did_info.did);

    // 4. Store test data
    println!("\n4. Storing test data...");
    let test_data = json!({
        "message": "This data will be cryptographically verified",
        "timestamp": chrono::Utc::now().timestamp(),
        "verified": true
    });

    match client
        .data()
        .store_item("test-app", "secure-data", "entry-1", test_data)
        .await
    {
        Ok(_) => println!("   Data stored"),
        Err(e) => println!("   Note: {}", e),
    }

    // 5. Retrieve with full trustless verification
    println!("\n5. Retrieving data with trustless verification...");
    println!("   This verifies:");
    println!("   - 2/3+ validator signatures on block headers");
    println!("   - GroveDB Merkle proof against consensus app_hash");
    println!("   - Data integrity without trusting any single node\n");

    match client.data().get("test-app", "secure-data", "entry-1").await {
        Ok(data) => {
            println!("   Data retrieved and CRYPTOGRAPHICALLY VERIFIED:");
            println!("   {}", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 6. Query with verification
    println!("\n6. Querying with trustless verification...");
    let query = json!({ "limit": 10 });

    match client.data().query("test-app", "secure-data", query).await {
        Ok(response) => {
            println!("   Query returned {} documents", response.documents.len());
            if let Some(root_hash) = &response.verified_root_hash {
                println!("   Verified against root: {}...", &root_hash[..16.min(root_hash.len())]);
            }
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 7. Export trusted state for persistence
    println!("\n7. Exporting trusted state...");
    if let Some(lc) = client.light_client() {
        let state = lc.export_trusted_state().await;
        println!("   Exported {} trusted headers", state.headers.len());

        // In production, you would serialize and save this:
        // let json = serde_json::to_string(&state)?;
        // std::fs::write("trusted_state.json", json)?;

        println!("   State can be persisted and restored later");
    }

    // 8. Show verification comparison
    println!("\n8. Verification comparison...");
    println!("\n   LIGHT CLIENT (trustless):");
    println!("   + Verifies validator signatures (2/3+ threshold)");
    println!("   + Validates block header chain");
    println!("   + Verifies proofs against consensus app_hash");
    println!("   + No trust in any single node required");
    println!("   - Slightly higher latency\n");

    println!("   STANDARD VERIFICATION (root hash):");
    println!("   + Fast verification");
    println!("   + Verifies GroveDB proofs locally");
    println!("   - Trusts that API returns correct root hash\n");

    println!("   UNVERIFIED (performance mode):");
    println!("   + Fastest response times");
    println!("   - Trusts the node completely");
    println!("   - Only use with trusted nodes");

    println!("\nLight client example complete!");
    Ok(())
}
