//! Register Subgrove Example
//!
//! Registers a new subgrove (data collection) in the Willow network.
//!
//! Run with: cargo run --example register_subgrove
//!
//! Prerequisites:
//! - Local Willow network running (./scripts/start_network.sh)
//! - An app must already be registered

use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use willow_sdk::{
    types::{FieldType, RegisterSubgroveRequest, SchemaDefinition},
    WillowClient, DEVNET_VALIDATOR_1,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // CONFIGURATION - Modify these values for your testing
    // =========================================================================
    let api_url = "http://localhost:3031";
    let consensus_url = "http://localhost:26657";

    // DID to use (must be subgrove owner or admin)
    let owner_did = DEVNET_VALIDATOR_1.did;
    let private_key_hex = DEVNET_VALIDATOR_1.private_key;
    let public_key_id = DEVNET_VALIDATOR_1.public_key_id;

    // Subgrove details
    let subgrove_id = "users";
    let subgrove_name = "Users Collection";

    let nonce: u64 = 2; // Must be > previous nonce; increment for each tx
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

    // Define schema (field name -> field type)
    let mut fields = BTreeMap::new();
    fields.insert("name".to_string(), FieldType::String);
    fields.insert("email".to_string(), FieldType::String);

    let request = RegisterSubgroveRequest {
        subgrove_id: subgrove_id.to_string(),
        name: subgrove_name.to_string(),
        description: String::new(),
        schema: Some(SchemaDefinition {
            version: 1,
            fields,
            required_fields: vec!["name".to_string(), "email".to_string()],
            indexes: vec![],
        }),
        owner_did: owner_did.to_string(),
        admins: vec![],
        initial_funding: None,
        writers: vec![owner_did.to_string()],
        readers: vec![], // empty = public read
        signature: vec![],
        public_key_id: public_key_id.to_string(),
        nonce,
    };

    println!("Registering subgrove: {}", subgrove_id);

    match client
        .consensus()
        .register_subgrove(request, &signing_key)
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
