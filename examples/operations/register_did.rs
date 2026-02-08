//! Register DID Example
//!
//! Registers a new DID on the Willow network.
//!
//! Run with: cargo run --example register_did
//!
//! Prerequisites:
//! - Local Willow network running (./scripts/start_network.sh)
//! - The DID must have a balance to pay the registration fee (1 WILL)
//!   (fund via bridge or transfer from another account first)

use willow_sdk::{auth::generate_did, types::SignatureAlgorithm, WillowClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // CONFIGURATION - Modify these values for your testing
    // =========================================================================
    let api_url = "http://localhost:3031";
    let consensus_url = "http://localhost:26657";
    let algorithm = SignatureAlgorithm::Ed25519;
    let nonce: u64 = 0; // First transaction for this DID
                        // =========================================================================

    let client = WillowClient::builder()
        .api_url(api_url)
        .consensus_url(consensus_url)
        .build()
        .await?;

    // Generate a new DID
    let did_info = generate_did(algorithm)?;

    println!("Registering DID: {}", did_info.did);
    println!("Public Key ID: {}", did_info.public_key_id);
    println!("Private Key (save this!): {}", did_info.private_key_hex());

    match client
        .consensus()
        .register_did(
            &did_info.did_document,
            &did_info.private_key_hex(),
            &did_info.public_key_id,
            algorithm,
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
