//! Transfer Tokens Example
//!
//! Transfers WILL tokens between DIDs.
//!
//! Run with: cargo run --example transfer
//!
//! Prerequisites:
//! - Local Willow network running (./scripts/start_network.sh)
//! - Sender DID must have sufficient balance

use willow_sdk::{types::SignatureAlgorithm, WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // CONFIGURATION - Modify these values for your testing
    // =========================================================================
    let api_url = "http://localhost:3031";
    let consensus_url = "http://localhost:26657";

    // Sender (must have balance)
    let from_did = DEVNET_VALIDATOR_1.did;
    let private_key = DEVNET_VALIDATOR_1.private_key;
    let public_key_id = DEVNET_VALIDATOR_1.public_key_id;

    // Recipient (can be any DID string, even unregistered)
    let to_did = "did:willow:recipient123";

    // Amount to transfer (in base units, 18 decimals)
    let amount: u128 = 1_000_000_000_000_000_000; // 1 WILL

    let memo = Some("Test transfer".to_string());
    let nonce: u64 = 0; // Increment for each transaction from this DID
                        // =========================================================================

    let client = WillowClient::builder()
        .api_url(api_url)
        .consensus_url(consensus_url)
        .build()
        .await?;

    println!("Transferring {} tokens", amount);
    println!("From: {}", from_did);
    println!("To: {}", to_did);

    match client
        .consensus()
        .transfer(
            from_did,
            to_did,
            amount,
            memo,
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
