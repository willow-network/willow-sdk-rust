//! Query Data Example
//!
//! Queries data from a subgrove.
//!
//! Run with: cargo run --example query_data
//!
//! Prerequisites:
//! - Local Willow network running (./scripts/start_network.sh)
//! - Data must exist in the subgrove

use serde_json::json;
use willow_sdk::{WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // CONFIGURATION - Modify these values for your testing
    // =========================================================================
    let api_url = "http://localhost:3031";

    // Authentication (required for some queries)
    let did = DEVNET_VALIDATOR_1.did;
    let private_key = DEVNET_VALIDATOR_1.private_key;
    let public_key_id = DEVNET_VALIDATOR_1.public_key_id;

    // What to query
    let subgrove_id = "users";
    let key = "user-1";
    // =========================================================================

    let client = WillowClient::new(api_url).await?;

    client.set_identity(did, private_key, public_key_id);

    // Get a specific document by key
    println!("Getting: {}/{}", subgrove_id, key);
    match client.data().get_unverified(subgrove_id, key).await {
        Ok(data) => {
            println!("Document:");
            println!("  {}", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Query all documents in the subgrove
    println!("\nQuerying all: {}", subgrove_id);
    match client
        .data()
        .query_unverified(subgrove_id, json!({ "limit": 100 }))
        .await
    {
        Ok(response) => {
            println!("Found {} documents:", response.documents.len());
            for doc in &response.documents {
                println!("  {}", serde_json::to_string(doc)?);
            }
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    Ok(())
}
