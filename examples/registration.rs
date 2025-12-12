//! Registration example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Generating DIDs with different signature algorithms
//! - Registering a DID
//! - Querying apps and subgroves
//!
//! Note: Creating apps and subgroves requires submitting transactions
//! through the consensus layer. This example shows the read operations
//! available through the SDK.
//!
//! Run with: cargo run --example registration

use willow_sdk::{
    auth::generate_did,
    types::SignatureAlgorithm,
    WillowClient,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Willow SDK - Registration Example");
    println!("==================================\n");

    let client = WillowClient::new("http://localhost:3031").await?;

    // 1. Generate and register Ed25519 DID (recommended)
    println!("1. Generating Ed25519 DID (recommended)...");
    let ed25519_did = generate_did(SignatureAlgorithm::Ed25519)?;
    println!("   DID: {}", ed25519_did.did);
    println!("   Algorithm: Ed25519");
    println!("   Public Key ID: {}", ed25519_did.public_key_id);

    match client.register_did(&ed25519_did.did_document).await {
        Ok(_) => println!("   Registered successfully\n"),
        Err(e) => println!("   Note: {}\n", e),
    }

    // 2. Generate Secp256k1 DID (Ethereum-compatible)
    println!("2. Generating Secp256k1 DID (Ethereum-compatible)...");
    let secp256k1_did = generate_did(SignatureAlgorithm::Secp256k1)?;
    println!("   DID: {}", secp256k1_did.did);
    println!("   Algorithm: Secp256k1");
    println!("   Public Key ID: {}", secp256k1_did.public_key_id);

    match client.register_did(&secp256k1_did.did_document).await {
        Ok(_) => println!("   Registered successfully\n"),
        Err(e) => println!("   Note: {}\n", e),
    }

    // 3. Authenticate with Ed25519 DID
    println!("3. Authenticating...");
    client
        .authenticate(
            &ed25519_did.did,
            &ed25519_did.private_key_hex(),
            &ed25519_did.public_key_id,
        )
        .await?;
    println!("   Authenticated as: {}\n", ed25519_did.did);

    // 4. List registered apps
    println!("4. Listing registered apps...");
    match client.registration().list_apps().await {
        Ok(apps) => {
            if apps.is_empty() {
                println!("   No apps registered yet");
            } else {
                println!("   Found {} apps:", apps.len());
                for app in apps.iter().take(5) {
                    println!("   - {} ({})", app.name, app.app_id);
                    println!("     Owner: {}", app.owner_did);
                    println!("     Type: {}", app.app_type);
                }
            }
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 5. Get a specific app
    println!("\n5. Getting specific app...");
    let app_id = "test-app";
    match client.registration().get_app(app_id).await {
        Ok(app) => {
            println!("   App ID: {}", app.app_id);
            println!("   Name: {}", app.name);
            println!("   Description: {}", app.description);
            println!("   Owner: {}", app.owner_did);
            println!("   Admins: {:?}", app.admins);
        }
        Err(e) => println!("   Note: {} (app may not exist)", e),
    }

    // 6. List subgroves for an app
    println!("\n6. Listing subgroves for app...");
    match client.registration().list_subgroves(app_id).await {
        Ok(subgroves) => {
            if subgroves.is_empty() {
                println!("   No subgroves registered for this app");
            } else {
                println!("   Found {} subgroves:", subgroves.len());
                for sg in subgroves.iter().take(5) {
                    println!("   - {} ({})", sg.name, sg.subgrove_id);
                    println!("     Path: {:?}", sg.subgrove_path);
                    println!("     Writers: {:?}", sg.writers);
                }
            }
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 7. Get a specific subgrove
    println!("\n7. Getting specific subgrove...");
    let subgrove_id = "test-subgrove";
    match client.registration().get_subgrove(app_id, subgrove_id).await {
        Ok(sg) => {
            println!("   Subgrove ID: {}", sg.subgrove_id);
            println!("   Name: {}", sg.name);
            println!("   Schema version: {}", sg.schema.version);
            println!("   Fields: {:?}", sg.schema.fields.keys().collect::<Vec<_>>());
        }
        Err(e) => println!("   Note: {} (subgrove may not exist)", e),
    }

    // 8. Summary
    println!("\n8. Registration summary...");
    println!("   DID generation: generate_did(algorithm)");
    println!("   DID registration: client.register_did(did_document)");
    println!("   Query apps: client.registration().list_apps()");
    println!("   Query subgroves: client.registration().list_subgroves(app_id)");
    println!("\n   Note: Creating apps and subgroves requires consensus transactions");
    println!("   Use the ConsensusClient for registration operations.");

    println!("\nRegistration example complete!");
    Ok(())
}
