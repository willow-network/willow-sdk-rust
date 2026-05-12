//! Registration example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Generating DIDs with different signature algorithms
//! - Registering a DID through consensus transactions
//! - Using the pre-registered devnet test account
//! - Querying apps and subgroves
//!
//! Run with: cargo run --example registration

use willow_sdk::{auth::generate_did, types::SignatureAlgorithm, WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Willow SDK - Registration Example");
    println!("==================================\n");

    // Create client with both API and consensus endpoints
    let client = WillowClient::builder()
        .api_url("http://localhost:3031")
        .consensus_url("http://localhost:26657")
        .build()
        .await?;

    // 1. Show DID generation (Ed25519)
    println!("1. Generating Ed25519 DID...");
    let ed25519_did = generate_did(SignatureAlgorithm::Ed25519)?;
    println!("   DID: {}", ed25519_did.did);
    println!("   Algorithm: Ed25519");
    println!("   Public Key ID: {}", ed25519_did.public_key_id);
    println!();

    // 2. Show DID generation (Secp256k1 - Ethereum-compatible)
    println!("2. Generating Secp256k1 DID (Ethereum-compatible)...");
    let secp256k1_did = generate_did(SignatureAlgorithm::Secp256k1)?;
    println!("   DID: {}", secp256k1_did.did);
    println!("   Algorithm: Secp256k1");
    println!("   Public Key ID: {}", secp256k1_did.public_key_id);
    println!();

    // 3. Register DID through consensus (requires running node with CometBFT RPC)
    println!("3. Registering DID through consensus...");
    match client
        .consensus()
        .register_did(
            &ed25519_did.did_document,
            &ed25519_did.private_key_hex(),
            &ed25519_did.public_key_id,
            SignatureAlgorithm::Ed25519,
        )
        .await
    {
        Ok(tx_hash) => println!("   Registered! TX hash: {}\n", tx_hash),
        Err(e) => println!("   Note: {} (this is expected if DID already exists)\n", e),
    }

    // 4. Authenticate with devnet test account (pre-registered)
    println!("4. Authenticating with devnet test account...");
    println!("   DID: {}", DEVNET_VALIDATOR_1.did);
    client.set_identity(
        DEVNET_VALIDATOR_1.did,
        DEVNET_VALIDATOR_1.private_key,
        DEVNET_VALIDATOR_1.public_key_id,
    );
    println!("   Authenticated successfully\n");

    // 5. List registered subgroves
    println!("5. Listing registered subgroves...");
    match client.registration().list_subgroves().await {
        Ok(subgroves) => {
            if subgroves.is_empty() {
                println!("   No subgroves registered yet");
            } else {
                println!("   Found {} subgroves:", subgroves.len());
                for sg in subgroves.iter().take(5) {
                    println!("   - {} ({})", sg.name, sg.subgrove_id);
                    println!("     Owner: {}", sg.owner_did);
                }
            }
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 6. Get a specific subgrove
    println!("\n6. Getting specific subgrove...");
    let subgrove_id = "test-subgrove";
    match client.registration().get_subgrove(subgrove_id).await {
        Ok(sg) => {
            println!("   Subgrove ID: {}", sg.subgrove_id);
            println!("   Name: {}", sg.name);
            println!("   Schema version: {}", sg.schema.version);
            println!(
                "   Fields: {:?}",
                sg.schema.fields.keys().collect::<Vec<_>>()
            );
        }
        Err(e) => println!("   Note: {} (subgrove may not exist)", e),
    }

    // 7. Summary
    println!("\n7. Registration summary...");
    println!("   DID generation: generate_did(algorithm)");
    println!("   DID registration: client.consensus().register_did(...)");
    println!("   Query subgroves: client.registration().list_subgroves()");
    println!("\n   Note: Creating subgroves requires consensus transactions");
    println!("   Use client.consensus() for registration operations.");

    println!("\nRegistration example complete!");
    Ok(())
}
