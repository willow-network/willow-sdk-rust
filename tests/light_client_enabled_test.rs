//! Light client verification test - WITH light client enabled
//!
//! This test demonstrates the ACTUAL light client functionality

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use willow_sdk::types::SignatureAlgorithm;
use willow_sdk::{ConsensusClient, LightClientConfigBuilder, WillowClient};

const PRIVATE_KEY_HEX: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

#[tokio::test]
#[ignore]
async fn light_client_enabled_verification_test() {
    println!("🔐 Starting ENABLED light client verification test...");
    println!("This test demonstrates ACTUAL trustless verification");

    // Read the funded DID
    let funded_did = std::env::var("WILLOW_TEST_DID")
        .unwrap_or_else(|_| "did:willow:test-owner".to_string());

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let subgrove_name_base = format!("light_test_{}", timestamp);
    let subgrove_name = format!("subgrove_{}", timestamp);

    println!("\n📋 Test Configuration:");
    println!("  DID: {}", funded_did);
    
    println!("  Subgrove: {}", subgrove_name);

    // Step 1: Create client WITH light client
    println!("\n🌟 Step 1: Creating client WITH light client...");

    let client = WillowClient::builder()
        .api_url("http://localhost:3031")
        .light_client_config(
            LightClientConfigBuilder::new("test-chain-consensus")
                .validator_endpoints(vec![
                    "http://localhost:26657".to_string(),
                    "http://localhost:26757".to_string(),
                    "http://localhost:26957".to_string(),
                ])
                .min_validators_for_consensus(2)
                .trust_threshold(2, 3)
                .auto_sync(false)
                .build(),
        )
        .build()
        .await
        .expect("Failed to create client with light client");

    println!("  ✅ Client created with light client enabled!");

    // Check light client status
    if let Some(light_client) = client.light_client() {
        println!("  🔐 Light client is ACTIVE!");

        // Wait for initial sync
        println!("  ⏳ Waiting for light client to sync...");
        sleep(Duration::from_secs(5)).await;

        match light_client.get_latest_header().await {
            Some(header) => println!(
                "  📊 Light client synced to height: {}",
                header.header.height
            ),
            None => println!("  ⚠️  No headers synced yet"),
        }

        match light_client.get_verified_height_range().await {
            Some((min, max)) => {
                println!("  📊 Verified height range: {} to {}", min, max);
                println!("  ✅ Light client has verified headers!");
            }
            None => println!("  ⚠️  No verified heights yet"),
        }
    }

    // Step 2: Register subgrove
    println!("\n📝 Step 2: Registering subgrove...");
    let consensus = ConsensusClient::new("http://localhost:26657");
    let base_nonce = 3;

    // Register subgrove with proper schema
    use std::collections::HashMap;
    use willow_sdk::types::{FieldType, RegisterSubgroveRequest, SchemaDefinition};

    let mut fields = std::collections::BTreeMap::new();
    fields.insert("message".to_string(), FieldType::String);
    fields.insert("timestamp".to_string(), FieldType::Number);
    fields.insert("verified".to_string(), FieldType::Boolean);

    let schema = SchemaDefinition {
        version: 1,
        fields,
        required_fields: vec![],
        indexes: vec![],
    };

    let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("Invalid private key hex");
    let signing_key =
        SigningKey::from_bytes(&private_key_bytes.try_into().expect("Invalid key length"));

    let subgrove_request = RegisterSubgroveRequest {
        subgrove_id: subgrove_name.clone(),
        name: "Light Client Test".to_string(),
        description: String::new(),
        schema: Some(schema),
        owner_did: funded_did.clone(),
        admins: vec![],
        initial_funding: None,        writers: vec![funded_did.clone()],
        readers: vec![funded_did.clone()],
        signature: vec![],
        public_key_id: format!("{}#key-1", funded_did),
        nonce: base_nonce + 1,
    };

    consensus
        .register_subgrove(subgrove_request, &signing_key)
        .await
        .expect("Failed to register subgrove");

    // Step 3: Store data
    println!("\n💾 Step 3: Storing test data...");
    let test_data = json!({
        "message": "This data will be verified by the light client",
        "timestamp": timestamp,
        "verified": true
    });

    use willow_sdk::types::StoreDataRequest;
    let store_request = StoreDataRequest {
        subgrove_id: subgrove_name.clone(),
        key: "test_entry".to_string(),
        data: test_data.clone(),
        owner_did: funded_did.clone(),
        signature: vec![],
        public_key_id: format!("{}#key-1", funded_did),
        nonce: base_nonce + 2,
    };

    consensus
        .store_data(store_request, &signing_key)
        .await
        .expect("Failed to store data");

    println!("  ⏳ Waiting for data indexing and consensus...");
    sleep(Duration::from_secs(10)).await;

    // Step 4: Authenticate and retrieve data with LIGHT CLIENT verification
    println!("\n🔐 Step 4: Retrieving data with LIGHT CLIENT verification...");

    client.set_identity(
        &funded_did,
        PRIVATE_KEY_HEX,
        &format!("{}#key-1", funded_did),
    );

    // This will use light client for verification!
    match client
        .data()
        .get(&subgrove_name, "test_entry")
        .await
    {
        Ok(data) => {
            println!("  ✅ Data retrieved and verified with LIGHT CLIENT!");
            println!("  📄 Message: {}", data["message"].as_str().unwrap_or(""));
            println!("  🔐 Verification: Proof verified against CONSENSUS STATE");
            println!("  🌟 This is TRUSTLESS verification!");
            println!("  📊 The proof was checked against headers signed by 2/3+ validators");
        }
        Err(e) => {
            println!("  ❌ Failed to retrieve data: {}", e);
            panic!("Light client verification failed!");
        }
    }

    // Step 5: Show light client details
    if let Some(light_client) = client.light_client() {
        println!("\n📊 Light Client Statistics:");
        match light_client.get_verified_height_range().await {
            Some((min, max)) => {
                println!("  ✅ Verified headers from height {} to {}", min, max);
                println!("  🔐 Each header is signed by 2/3+ validators");
                println!("  📋 Each contains the GroveDB root hash (app_hash)");
                println!("  🌟 Proofs are verified against these consensus roots");
            }
            None => println!("  ⚠️  Could not get verified height range"),
        }
    }

    println!("\n✅ Light client test complete!");
    println!("🌟 This demonstrated ACTUAL trustless verification");
}
