//! Proof verification example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Automatic proof verification (default behavior)
//! - Comparing verified vs unverified operations
//! - How proofs work behind the scenes
//!
//! Run with: cargo run --example proof_verification

use serde_json::json;
use willow_sdk::{WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Willow SDK - Proof Verification Example");
    println!("========================================\n");

    // Setup: authenticate with devnet test account
    let client = WillowClient::new("http://localhost:3031").await?;
    client
        .authenticate(
            DEVNET_VALIDATOR_1.did,
            DEVNET_VALIDATOR_1.private_key,
            DEVNET_VALIDATOR_1.public_key_id,
        )
        .await?;

    println!("Authenticated as: {}\n", DEVNET_VALIDATOR_1.did);

    let app_id = "proof-demo";
    let subgrove_id = "test-data";

    // 1. Store test data
    println!("1. Storing test data...");
    let test_data = json!({
        "message": "This data has a cryptographic proof",
        "value": 42
    });

    match client
        .data()
        .store_item(app_id, subgrove_id, "test-key", test_data)
        .await
    {
        Ok(_) => println!("   Data stored\n"),
        Err(e) => println!("   Note: {}\n", e),
    }

    // 2. Get with automatic verification (default)
    println!("2. Get with automatic verification...");
    println!("   The SDK automatically:");
    println!("   - Requests the data from the API");
    println!("   - Fetches the proof for that item");
    println!("   - Verifies the proof using the light client (if configured)");
    println!("   - Compares against the consensus root hash");
    println!("   - Returns error if verification fails\n");

    match client.data().get(app_id, subgrove_id, "test-key").await {
        Ok(data) => {
            println!("   Data retrieved and VERIFIED:");
            println!("   {}\n", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 3. Get without verification (faster)
    println!("3. Get without verification (unverified)...");
    println!("   Skips all proof verification for maximum performance");
    println!("   Use only when you trust the node\n");

    match client
        .data()
        .get_unverified(app_id, subgrove_id, "test-key")
        .await
    {
        Ok(data) => {
            println!("   Data retrieved (no verification):");
            println!("   {}\n", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 4. Query with verification
    println!("4. Query with automatic verification...");
    let query = json!({ "limit": 5 });

    match client
        .data()
        .query(app_id, subgrove_id, query.clone())
        .await
    {
        Ok(response) => {
            println!("   Found {} documents", response.documents.len());
            if let Some(root_hash) = &response.verified_root_hash {
                println!(
                    "   Verified against root: {}...",
                    &root_hash[..32.min(root_hash.len())]
                );
            }
            if response.proof.is_some() {
                println!("   Proof was included and verified\n");
            }
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 5. Query without verification (for comparison)
    println!("5. Query without verification (unverified)...");
    match client
        .data()
        .query_unverified(app_id, subgrove_id, query)
        .await
    {
        Ok(response) => {
            println!("   Found {} documents", response.documents.len());
            println!("   No verification performed");
            println!("   Proof included: {}\n", response.proof.is_some());
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 6. Root hash comparison
    println!("6. Root hash comparison...");
    let verified_root = client.get_root_hash().await.ok();
    let local_root = client.get_root_hash_local().await.ok();

    match (verified_root, local_root) {
        (Some(v), Some(l)) => {
            println!("   Consensus root: {}...", &v[..32.min(v.len())]);
            println!("   Local root:     {}...", &l[..32.min(l.len())]);
            if v == l {
                println!("   Node is in sync with consensus\n");
            } else {
                println!("   Node has pending changes\n");
            }
        }
        _ => println!("   Could not retrieve root hashes\n"),
    }

    // 7. Summary
    println!("7. Proof verification summary...");
    println!("\n   AUTOMATIC VERIFICATION (recommended):");
    println!("   - Use get() and query() methods");
    println!("   - Proofs verified against consensus root hash");
    println!("   - Returns error if verification fails");
    println!("   - Provides cryptographic guarantee of data integrity\n");

    println!("   WITH LIGHT CLIENT (trustless):");
    println!("   - Configure with LightClientConfigBuilder");
    println!("   - Verifies validator signatures (2/3+ threshold)");
    println!("   - No trust required in any single node\n");

    println!("   SKIP VERIFICATION (use with caution):");
    println!("   - Use get_unverified() and query_unverified()");
    println!("   - Maximum performance");
    println!("   - Only with trusted nodes");

    println!("\nProof verification example complete!");
    Ok(())
}
