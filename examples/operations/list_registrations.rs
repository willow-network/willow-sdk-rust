//! List Registrations Example
//!
//! Lists registered subgroves.
//!
//! Run with: cargo run --example list_registrations
//!
//! Prerequisites:
//! - Local Willow network running (./scripts/start_network.sh)

use willow_sdk::{WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // CONFIGURATION - Modify these values for your testing
    // =========================================================================
    let api_url = "http://localhost:3031";

    // Authentication
    let did = DEVNET_VALIDATOR_1.did;
    let private_key = DEVNET_VALIDATOR_1.private_key;
    let public_key_id = DEVNET_VALIDATOR_1.public_key_id;

    // =========================================================================
    // =========================================================================

    let client = WillowClient::new(api_url).await?;

    client.set_identity(did, private_key, public_key_id);

    // List all subgroves
    println!("Registered Subgroves:");
    match client.registration().list_subgroves().await {
        Ok(subgroves) => {
            if subgroves.is_empty() {
                println!("  (none)");
            }
            for sg in &subgroves {
                println!("  - {} ({})", sg.subgrove_id, sg.name);
            }
        }
        Err(e) => println!("  Error: {}", e),
    }

    Ok(())
}
