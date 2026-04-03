//! Test for fresh network state - run after restarting network

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;
use willow_sdk::{ConsensusClient, WillowClient};

const PRIVATE_KEY_HEX: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

#[tokio::test]
#[ignore] // Run with: cargo test fresh_test -- --ignored
async fn fresh_test() {
    println!("Starting fresh network test...");
    println!("This test assumes:");
    println!("- DID is registered (nonce 1)");
    println!("- Subgrove is registered (nonce 2)");
    println!("- Network was just restarted");

    // Read the funded DID
    let funded_did = std::env::var("WILLOW_TEST_DID")
        .unwrap_or_else(|_| "did:willow:test-owner".to_string());

    println!("\nUsing funded DID: {}", funded_did);

    let client = WillowClient::new("http://localhost:3031").await.unwrap();
    let _consensus = ConsensusClient::new("http://localhost:26657");

    let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("Invalid private key hex");
    let signing_key =
        SigningKey::from_bytes(&private_key_bytes.try_into().expect("Invalid key length"));

    // Step 1: Register subgrove with nonce 3
    println!("\nStep 1: Registering subgrove with nonce 3...");

    use sha3::{Digest, Keccak256};
    let schema = json!({
        "version": 1,
        "fields": {
            "title": "string",
            "content": "string",
            "author": "string",
            "timestamp": "number"
        },
        "indexes": [],
        "required_fields": ["title", "content", "author", "timestamp"]
    });

    let schema_json = serde_json::to_string(&schema).unwrap();

    // Hash the schema
    let mut hasher = Keccak256::new();
    hasher.update(schema_json.as_bytes());
    let schema_hash = hasher.finalize();
    let schema_hash_hex = hex::encode(schema_hash);

    // Create message to sign
    let message = format!(
        "RegisterSubgrove\nID: posts\nName: Blog Posts\nSchemaHash: {}\nOwner: {}\nWriters: \nReaders: \nNonce: 3",
        schema_hash_hex,
        funded_did
    );

    // Sign with Ed25519 key
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(message.as_bytes());

    // Create transaction directly
    let transaction = json!({
        "RegisterSubgrove": {
            "subgrove_id": "posts",
            
            "name": "Blog Posts",
            "schema": schema_json,
            "owner_did": funded_did.clone(),
            "writers": [],
            "readers": [],
            "signature": signature.to_bytes().to_vec(),
            "public_key_id": format!("{}#key-1", funded_did),
            "nonce": 3,
        }
    });

    // Submit directly
    let tx_json = serde_json::to_string(&transaction).unwrap();
    use base64::Engine as _;
    let tx_base64 = base64::engine::general_purpose::STANDARD.encode(tx_json.as_bytes());

    let rpc_request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "broadcast_tx_sync",
        "params": {
            "tx": tx_base64
        }
    });

    let http_client = reqwest::Client::new();
    let response = http_client
        .post("http://localhost:26657")
        .json(&rpc_request)
        .send()
        .await
        .unwrap();

    let response_text = response.text().await.unwrap();
    println!("Subgrove registration response: {}", response_text);

    // Wait for transaction to be processed and indexed
    println!("Waiting for subgrove to be fully initialized...");
    sleep(Duration::from_secs(10)).await;

    // Step 2: Fund subgrove (no nonce)
    println!("\nStep 2: Funding subgrove...");

    let fund_tx = json!({
        "FundSubgrove": {
            
            "amount": 10_000_000_000_000_000_000u128,
            "from_did": funded_did.clone(),
            "signature": []
        }
    });

    let tx_json = serde_json::to_string(&fund_tx).unwrap();
    let tx_base64 = base64::engine::general_purpose::STANDARD.encode(tx_json.as_bytes());

    let rpc_request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "broadcast_tx_sync",
        "params": {
            "tx": tx_base64
        }
    });

    let response = http_client
        .post("http://localhost:26657")
        .json(&rpc_request)
        .send()
        .await
        .unwrap();

    let response_text = response.text().await.unwrap();
    println!("Fund subgrove response: {}", response_text);

    println!("Waiting for subgrove funding to be processed...");
    sleep(Duration::from_secs(10)).await;

    // Step 3: Store data with nonce 4
    println!("\nStep 3: Storing data with nonce 4...");

    let data = json!({
        "title": "Test Post",
        "content": "This is a test post",
        "author": "alice",
        "timestamp": 1234567890
    });

    let data_json = serde_json::to_string(&data).unwrap();
    let message = format!("posts:post1:{}", data_json);

    let signature = signing_key.sign(message.as_bytes());

    let store_tx = json!({
        "StoreData": {
            
            "subgrove_id": "posts",
            "key": "post1",
            "data": data,
            "owner_did": funded_did.clone(),
            "signature": signature.to_bytes().to_vec(),
            "public_key_id": format!("{}#key-1", funded_did),
            "nonce": 4
        }
    });

    let tx_json = serde_json::to_string(&store_tx).unwrap();
    let tx_base64 = base64::engine::general_purpose::STANDARD.encode(tx_json.as_bytes());

    let rpc_request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "broadcast_tx_sync",
        "params": {
            "tx": tx_base64
        }
    });

    let response = http_client
        .post("http://localhost:26657")
        .json(&rpc_request)
        .send()
        .await
        .unwrap();

    let response_text = response.text().await.unwrap();
    println!("Store data response: {}", response_text);

    println!("Waiting for data to be indexed...");
    sleep(Duration::from_secs(15)).await;

    // Step 4: Read data
    println!("\nStep 4: Reading data...");

    // Set identity
    client.set_identity(
        &funded_did,
        PRIVATE_KEY_HEX,
        &format!("{}#key-1", funded_did),
    );

    // Read data
    match client.data().get("posts", "post1").await {
        Ok(data) => {
            println!("✅ Successfully retrieved data:");
            println!("{}", serde_json::to_string_pretty(&data).unwrap());
        }
        Err(e) => {
            println!("❌ Failed to read data: {}", e);
        }
    }

    println!("\n✅ Test completed!");
}
