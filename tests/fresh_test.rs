//! Test for fresh network state - run after restarting network

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;
use willow_sdk::{ConsensusClient, WillowClient};

// RFC 8032 §7.1 Test 2 Ed25519 vector.
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
    let funded_did =
        std::env::var("WILLOW_TEST_DID").unwrap_or_else(|_| "did:willow:test-owner".to_string());

    println!("\nUsing funded DID: {}", funded_did);

    let client = WillowClient::new("http://localhost:3031").await.unwrap();
    let consensus = ConsensusClient::new("http://localhost:26657");

    let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("Invalid private key hex");
    let signing_key =
        SigningKey::from_bytes(&private_key_bytes.try_into().expect("Invalid key length"));

    // Step 1: Register subgrove with nonce 3
    println!("\nStep 1: Registering subgrove with nonce 3...");

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

    // Every field is sent explicitly; the signature binds them all through `Config`.
    use ed25519_dalek::Signer;
    use willow_sdk::consensus::SubgroveMode;
    use willow_sdk::signed_messages::{self, RegisterSubgroveTx};
    let mut register_tx = RegisterSubgroveTx {
        subgrove_id: "posts".to_string(),
        name: "Blog Posts".to_string(),
        description: String::new(),
        schema: serde_json::to_string(&schema).unwrap(),
        owner_did: funded_did.clone(),
        admins: vec![],
        initial_funding: None,
        checkpoint_verification: Default::default(),
        mode: SubgroveMode::DataStorage {
            name: "Blog Posts".to_string(),
            writers: vec![],
            free_readers: vec![],
            read_pricing: None,
        },
        privacy: None,
        initial_owner_key_grant: None,
        template_config: None,
        confirmation_depth: 0,
        signature: vec![],
        public_key_id: format!("{}#key-1", funded_did),
        nonce: 3,
        cryptographic_completeness: false,
    };
    let message = signed_messages::register_subgrove(&register_tx).unwrap();
    register_tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();

    let tx_json = ConsensusClient::serialize_tx("RegisterSubgrove", &register_tx).unwrap();
    let response = consensus.submit_transaction_json(&tx_json).await;
    println!("Subgrove registration response: {:?}", response);

    use base64::Engine as _;
    let http_client = reqwest::Client::new();

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
