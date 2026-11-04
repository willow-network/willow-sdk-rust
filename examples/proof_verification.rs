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
    client.set_identity(
        DEVNET_VALIDATOR_1.did,
        DEVNET_VALIDATOR_1.private_key,
        DEVNET_VALIDATOR_1.public_key_id,
    );

    println!("Authenticated as: {}\n", DEVNET_VALIDATOR_1.did);

    let subgrove_id = "test-data";

    // 1. Get with automatic verification (default)
    // Note: Data must first be stored via consensus transactions
    println!("1. Get with automatic verification...");
    println!("   The SDK automatically:");
    println!("   - Requests the data from the API");
    println!("   - Fetches the proof for that item");
    println!("   - Checks the proof proves that value at its key");
    println!("   - Compares its root with the header after the proof's block");
    println!("   - Returns error if verification fails\n");

    match client.data().get(subgrove_id, "test-key").await {
        Ok(data) => {
            println!("   Data retrieved and VERIFIED:");
            println!("   {}\n", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 2. Get without verification (faster)
    println!("2. Get without verification (unverified)...");
    println!("   Skips all proof verification for maximum performance");
    println!("   Use only when you trust the node\n");

    match client.data().get_unverified(subgrove_id, "test-key").await {
        Ok(data) => {
            println!("   Data retrieved (no verification):");
            println!("   {}\n", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 3. Query: refused, since nothing binds a query's documents to a proof
    println!("3. Query with verification (refused)...");
    let query = json!({ "limit": 5 });

    match client.data().query(subgrove_id, query.clone()).await {
        Ok(response) => println!("   Found {} documents\n", response.documents.len()),
        Err(e) => println!("   Note: {}\n", e),
    }

    // 4. Query without verification (for comparison)
    println!("4. Query without verification (unverified)...");
    match client.data().query_unverified(subgrove_id, query).await {
        Ok(response) => {
            println!("   Found {} documents", response.documents.len());
            println!("   No verification performed");
            println!("   Proof included: {}\n", response.proof.is_some());
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 5. Root hash comparison (both are the API's word, unverified)
    println!("5. Root hash comparison (as the API reports them)...");
    let verified_root = client.get_root_hash().await.ok();
    let local_root = client.get_root_hash_local().await.ok();

    match (verified_root, local_root) {
        (Some(v), Some(l)) => {
            println!("   Committed root: {}...", &v[..32.min(v.len())]);
            println!("   Local root:     {}...", &l[..32.min(l.len())]);
            if v == l {
                println!("   Node is in sync with consensus\n");
            } else {
                println!("   Node has pending changes\n");
            }
        }
        _ => println!("   Could not retrieve root hashes\n"),
    }

    // 6. Summary
    println!("6. Proof verification summary...");
    println!("\n   VERIFIED READS:");
    println!("   - get() returns a value only when its proof binds it at its key");
    println!("     and its root is the app_hash of the header after the proof's block");
    println!("   - The header comes from the light client's validator endpoints");
    println!("     (commit signatures are not checked)");
    println!("   - query() refuses: a query's documents aren't bound to its proof\n");

    println!("   UNVERIFIED (use with caution):");
    println!("   - Use get_unverified() and query_unverified()");
    println!("   - Maximum performance");
    println!("   - Only with trusted nodes");

    println!("\nProof verification example complete!");
    Ok(())
}
