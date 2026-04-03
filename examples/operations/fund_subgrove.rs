//! Fund Subgrove Example
//!
//! Funds a subgrove with WILL tokens.
//!
//! Run with: cargo run --example fund_subgrove
//!
//! Prerequisites:
//! - Local Willow network running (./scripts/start_network.sh)
//! - A subgrove must already be registered
//! - Funder DID must have sufficient balance

use ed25519_dalek::SigningKey;
use willow_sdk::{types::FundSubgroveRequest, WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // CONFIGURATION - Modify these values for your testing
    // =========================================================================
    let api_url = "http://localhost:3031";
    let consensus_url = "http://localhost:26657";

    // Funder (must have balance)
    let from_did = DEVNET_VALIDATOR_1.did;
    let private_key_hex = DEVNET_VALIDATOR_1.private_key;
    let public_key_id = DEVNET_VALIDATOR_1.public_key_id;

    // Subgrove to fund (must exist)
    let subgrove_id = "my-subgrove";

    // Amount to fund (in base units, 18 decimals)
    let amount: u128 = 10_000_000_000_000_000_000; // 10 WILL

    let nonce: u64 = 3; // Must be > previous nonce; increment for each tx
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

    let request = FundSubgroveRequest {
        subgrove_id: subgrove_id.to_string(),
        amount,
        from_did: from_did.to_string(),
        signature: vec![],
        public_key_id: public_key_id.to_string(),
        nonce,
    };

    println!("Funding subgrove: {}", subgrove_id);
    println!("Amount: {} tokens", amount);
    println!("From: {}", from_did);

    match client.consensus().fund_subgrove(request, &signing_key).await {
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
