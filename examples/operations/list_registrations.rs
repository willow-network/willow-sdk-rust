//! List Registrations Example
//!
//! Lists registered apps and subgroves.
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

    // Optional: specific app to list subgroves for
    let app_id = Some("my-app");
    // =========================================================================

    let client = WillowClient::new(api_url).await?;

    client.set_identity(did, private_key, public_key_id);

    // List all apps
    println!("Registered Apps:");
    match client.registration().list_apps().await {
        Ok(apps) => {
            if apps.is_empty() {
                println!("  (none)");
            }
            for app in &apps {
                println!("  - {} ({})", app.app_id, app.app_type);
            }
        }
        Err(e) => println!("  Error: {}", e),
    }

    // List subgroves for specific app
    if let Some(app) = app_id {
        println!("\nSubgroves for '{}':", app);
        match client.registration().list_subgroves(app).await {
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
    }

    Ok(())
}
