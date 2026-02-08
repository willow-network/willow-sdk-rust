//! Store Data Example
//!
//! Stores data in a subgrove through consensus.
//!
//! Run with: cargo run --example store_data
//!
//! Prerequisites:
//! - Local Willow network running (./scripts/start_network.sh)
//! - An app and subgrove must already be registered

use ed25519_dalek::SigningKey;
use serde_json::json;
use willow_sdk::{types::StoreDataRequest, WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // CONFIGURATION - Modify these values for your testing
    // =========================================================================
    let api_url = "http://localhost:3031";
    let consensus_url = "http://localhost:26657";

    // DID to use (must have write access to the subgrove)
    let owner_did = DEVNET_VALIDATOR_1.did;
    let private_key_hex = DEVNET_VALIDATOR_1.private_key;
    let public_key_id = DEVNET_VALIDATOR_1.public_key_id;

    // Where to store
    let app_id = "my-app"; // Must exist
    let subgrove_id = "users"; // Must exist

    // What to store
    let key = "user-1";
    let data = json!({
        "name": "Alice",
        "email": "alice@example.com"
    });

    let nonce: u64 = 2; // Increment for each transaction from this DID
                        // =========================================================================

    let client = WillowClient::builder()
        .api_url(api_url)
        .consensus_url(consensus_url)
        .build()
        .await?;

    // Create signing key
    let private_key_bytes = hex::decode(private_key_hex)?;
    let signing_key = SigningKey::from_bytes(
        &private_key_bytes
            .try_into()
            .map_err(|_| "Invalid key length")?,
    );

    let request = StoreDataRequest {
        app_id: app_id.to_string(),
        subgrove_id: subgrove_id.to_string(),
        key: key.to_string(),
        data: data.clone(),
        owner_did: owner_did.to_string(),
        signature: vec![],
        public_key_id: public_key_id.to_string(),
        nonce,
    };

    println!("Storing data: {}/{}/{}", app_id, subgrove_id, key);
    println!("Data: {}", data);

    match client.consensus().store_data(request, &signing_key).await {
        Ok(tx_hash) => {
            println!("SUCCESS! TX: {}", tx_hash);
            client.consensus().wait_for_transaction(&tx_hash, 5).await?;
            println!("Confirmed!");
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    Ok(())
}
