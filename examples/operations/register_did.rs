//! Register DID Example
//!
//! Registers a new DID on the Willow network.
//!
//! Run with: cargo run --example register_did
//!
//! Willow DIDs are self-certifying: the id is *derived* from the public key
//! (`did:willow:z...`), not chosen. Registration therefore follows a two-step
//! bootstrap:
//!   1. Generate the keypair and read the derived `did` (below).
//!   2. Have an existing account transfer >= the registration fee (1 WILL) to
//!      that derived `did`.
//!   3. Register; the fee is paid from the balance funded in step 2.
//!
//! Prerequisites:
//! - Local Willow network running (./scripts/start_network.sh)
//! - The derived DID must already hold a balance to pay the registration fee
//!   (fund via transfer from another account first — see step 2 above)

use willow_sdk::{auth::generate_did, types::SignatureAlgorithm, WillowClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // CONFIGURATION - Modify these values for your testing
    // =========================================================================
    let api_url = "http://localhost:3031";
    let consensus_url = "http://localhost:26657";
    let algorithm = SignatureAlgorithm::Ed25519;
    // =========================================================================

    let client = WillowClient::builder()
        .api_url(api_url)
        .consensus_url(consensus_url)
        .build()
        .await?;

    // Generate a new DID
    let did_info = generate_did(algorithm)?;

    println!("Derived DID: {}", did_info.did);
    println!("Public Key ID: {}", did_info.public_key_id);
    println!("Private Key (save this!): {}", did_info.private_key_hex());
    println!(
        "NOTE: This id is derived from the key and cannot be chosen. Fund it with >= the \n\
         registration fee (transfer from an existing account) BEFORE registering."
    );

    match client
        .consensus()
        .register_did(
            &did_info.did_document,
            &did_info.private_key_hex(),
            &did_info.public_key_id,
            algorithm,
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
