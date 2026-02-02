//! Register App Example
//!
//! Registers a new application on the Willow network.
//!
//! Run with: cargo run --example register_app
//!
//! Prerequisites:
//! - Local Willow network running (./scripts/start_network.sh)
//! - A registered DID with sufficient balance

use willow_sdk::{types::SignatureAlgorithm, WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // CONFIGURATION - Modify these values for your testing
    // =========================================================================
    let api_url = "http://localhost:3031";
    let consensus_url = "http://localhost:26657";

    // DID to use (must be registered and have balance)
    let owner_did = DEVNET_VALIDATOR_1.did;
    let private_key = DEVNET_VALIDATOR_1.private_key;
    let public_key_id = DEVNET_VALIDATOR_1.public_key_id;

    // App details
    let app_id = "my-app"; // Change this to your app ID
    let app_name = "My Application";
    let app_description = "Description of my application";
    let app_type = "storage"; // "storage" or "indexing"

    let nonce: u64 = 0; // Increment for each transaction from this DID
    // =========================================================================

    let client = WillowClient::builder()
        .api_url(api_url)
        .consensus_url(consensus_url)
        .build()
        .await?;

    println!("Registering app: {}", app_id);
    println!("Owner: {}", owner_did);

    match client
        .consensus()
        .register_app(
            app_id,
            app_name,
            app_description,
            app_type,
            owner_did,
            vec![owner_did.to_string()], // admins
            private_key,
            public_key_id,
            SignatureAlgorithm::Ed25519,
            nonce,
        )
        .await
    {
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
