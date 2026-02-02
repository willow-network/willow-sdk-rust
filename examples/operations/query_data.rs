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
    let app_id = "my-app";
    let subgrove_id = "users";
    // =========================================================================

    let client = WillowClient::new(api_url).await?;

    client.authenticate(did, private_key, public_key_id).await?;

    println!("Querying: {}/{}", app_id, subgrove_id);

    // Query all documents
    match client
        .data()
        .query(app_id, subgrove_id, json!({ "limit": 100 }))
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
