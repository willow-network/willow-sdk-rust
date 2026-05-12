//! Basic indexing functionality test

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use willow_sdk::{ConsensusClient, WillowClient};

const PRIVATE_KEY_HEX: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

#[tokio::test]
#[ignore] // Run with: cargo test basic_indexing_test -- --ignored --nocapture
async fn basic_indexing_test() {
    println!("🚀 Starting basic indexing test...");
    println!("This test verifies core indexing functionality");

    // Read the funded DID
    let funded_did =
        std::env::var("WILLOW_TEST_DID").unwrap_or_else(|_| "did:willow:test-owner".to_string());

    // Generate unique subgrove name with timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let subgrove_name = format!("basic_posts_{}", timestamp);

    println!("\n📋 Test Configuration:");
    println!("  DID: {}", funded_did);
    println!("  Subgrove: test-subgrove");
    println!("  Subgrove: {}", subgrove_name);

    let client = WillowClient::new("http://localhost:3031").await.unwrap();
    let consensus = ConsensusClient::new("http://localhost:26657");

    let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("Invalid private key hex");
    let signing_key =
        SigningKey::from_bytes(&private_key_bytes.try_into().expect("Invalid key length"));

    // Step 1: Register subgrove with indexes
    println!("\n📝 Step 1: Registering subgrove with schema and indexes...");

    let schema = json!({
        "version": 1,
        "fields": {
            "title": "string",
            "content": "string",
            "author": "string",
            "category": "string",
            "tags": "array",
            "timestamp": "number",
            "views": "number"
        },
        "indexes": [
            {
                "name": "by_author",
                "fields": ["author"],
                "unique": false
            },
            {
                "name": "by_category",
                "fields": ["category"],
                "unique": false
            },
            {
                "name": "by_timestamp",
                "fields": ["timestamp"],
                "unique": false
            }
        ],
        "required_fields": ["title", "content", "author", "timestamp"]
    });

    let register_result = register_subgrove_direct(
        &consensus,
        &subgrove_name,
        "Basic Posts Test",
        &schema,
        &funded_did,
        &signing_key,
        3, // nonce after DID registration
    )
    .await;

    match register_result {
        Ok(tx_hash) => println!("  ✅ Subgrove registered: {}", tx_hash),
        Err(e) => println!(
            "  ⚠️  Subgrove registration error (may already exist): {}",
            e
        ),
    }

    println!("  ⏳ Waiting for subgrove initialization...");
    sleep(Duration::from_secs(10)).await;

    // Step 2: Fund the app
    println!("\n💰 Step 2: Funding the subgrove...");

    let fund_tx = json!({
        "FundSubgrove": {

            "amount": 10_000_000_000_000_000_000u128, // 10 WILL
            "from_did": funded_did.clone(),
            "signature": []
        }
    });

    match submit_transaction(&consensus, &fund_tx).await {
        Ok(tx_hash) => println!("  ✅ Subgrove funded: {}", tx_hash),
        Err(e) => println!("  ⚠️  Funding error (may already be funded): {}", e),
    }

    println!("  ⏳ Waiting for funding to process...");
    sleep(Duration::from_secs(10)).await;

    // Step 3: Store test documents
    println!("\n📊 Step 3: Storing test documents...");

    let documents = vec![
        (
            "post_1",
            json!({
                "title": "Introduction to Willow",
                "content": "Learn how Willow provides decentralized indexing with cryptographic proofs.",
                "author": "alice",
                "category": "tutorial",
                "tags": ["indexing", "tutorial", "basics"],
                "timestamp": 1000,
                "views": 150
            }),
        ),
        (
            "post_2",
            json!({
                "title": "Advanced Query Patterns",
                "content": "Explore complex query patterns and optimization techniques.",
                "author": "bob",
                "category": "advanced",
                "tags": ["query", "optimization", "advanced"],
                "timestamp": 2000,
                "views": 300
            }),
        ),
        (
            "post_3",
            json!({
                "title": "Building DApps with Willow",
                "content": "Step-by-step guide to building decentralized applications.",
                "author": "alice",
                "category": "tutorial",
                "tags": ["dapp", "tutorial", "development"],
                "timestamp": 3000,
                "views": 500
            }),
        ),
    ];

    let mut nonce = 4; // Starting nonce after subgrove registration

    for (key, data) in &documents {
        match store_data_direct(
            &consensus,
            &subgrove_name,
            key,
            data.clone(),
            &funded_did,
            &signing_key,
            nonce,
        )
        .await
        {
            Ok(tx_hash) => println!("  ✅ Stored {}: {}", key, tx_hash),
            Err(e) => println!("  ❌ Failed to store {}: {}", key, e),
        }
        nonce += 1;
        sleep(Duration::from_secs(2)).await; // Small delay between stores
    }

    println!("  ⏳ Waiting for indexing to complete...");
    sleep(Duration::from_secs(15)).await;

    // Step 4: Verify data retrieval
    println!("\n🔍 Step 4: Verifying data retrieval...");

    // Set identity
    client.set_identity(
        &funded_did,
        PRIVATE_KEY_HEX,
        &format!("{}#key-1", funded_did),
    );

    let mut success_count = 0;
    let mut failure_count = 0;

    for (key, expected_data) in &documents {
        match client.data().get(&subgrove_name, key).await {
            Ok(data) => {
                // Verify key fields
                if data["title"] == expected_data["title"]
                    && data["author"] == expected_data["author"]
                    && data["timestamp"] == expected_data["timestamp"]
                {
                    println!(
                        "  ✅ Retrieved {}: \"{}\" by {}",
                        key,
                        data["title"].as_str().unwrap_or(""),
                        data["author"].as_str().unwrap_or("")
                    );
                    success_count += 1;
                } else {
                    println!("  ❌ Data mismatch for {}", key);
                    failure_count += 1;
                }
            }
            Err(e) => {
                println!("  ❌ Failed to retrieve {}: {}", key, e);
                failure_count += 1;
            }
        }
    }

    // Step 5: Test basic query
    println!("\n🔎 Step 5: Testing basic query operations...");

    // Query by author
    let query = json!({
        "filters": { "author": "alice" },
        "limit": 10
    });

    match client.data().query(&subgrove_name, query).await {
        Ok(results) => {
            if results.documents.is_empty() {
                println!(
                    "  ⚠️  Query returned 0 documents - indexing may not be working correctly"
                );
                println!("     Expected to find documents by author 'alice'");
                failure_count += 1;
            } else {
                println!("  ✅ Query returned {} documents", results.documents.len());
                for doc in &results.documents {
                    println!(
                        "    - \"{}\" (timestamp: {})",
                        doc["title"].as_str().unwrap_or(""),
                        doc["timestamp"].as_i64().unwrap_or(0)
                    );
                }
            }
        }
        Err(e) => {
            println!(
                "  ⚠️  Query error: {} (query API may not be fully implemented)",
                e
            );
            failure_count += 1;
        }
    }

    // Summary
    println!("\n📊 Test Summary:");
    println!("  Total documents: {}", documents.len());
    println!("  Successfully retrieved: {}", success_count);
    println!("  Failed retrievals: {}", failure_count);

    if failure_count == 0 {
        println!("\n✅ Basic indexing test completed successfully!");
    } else {
        panic!("\n❌ Test failed with {} failures", failure_count);
    }
}

// Helper function to register subgrove directly
async fn register_subgrove_direct(
    consensus: &ConsensusClient,
    subgrove_id: &str,

    name: &str,
    schema: &serde_json::Value,
    owner_did: &str,
    signing_key: &SigningKey,
    nonce: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    use ed25519_dalek::Signer;
    use sha3::{Digest, Keccak256};

    let schema_json = serde_json::to_string(schema)?;

    // Hash the schema
    let mut hasher = Keccak256::new();
    hasher.update(schema_json.as_bytes());
    let schema_hash = hasher.finalize();
    let schema_hash_hex = hex::encode(schema_hash);

    // Create message to sign
    let message = format!(
        "RegisterSubgrove\nID: {}\nName: {}\nSchemaHash: {}\nOwner: {}\nWriters: \nReaders: \nNonce: {}",
        subgrove_id, name, schema_hash_hex, owner_did, nonce
    );

    // Sign with Ed25519 key
    let signature = signing_key.sign(message.as_bytes());

    // Create transaction
    let transaction = json!({
        "RegisterSubgrove": {
            "subgrove_id": subgrove_id,

            "name": name,
            "schema": schema_json,
            "owner_did": owner_did,
            "writers": [],
            "readers": [],
            "signature": signature.to_bytes().to_vec(),
            "public_key_id": format!("{}#key-1", owner_did),
            "nonce": nonce,
        }
    });

    submit_transaction(consensus, &transaction).await
}

// Helper function to store data directly
async fn store_data_direct(
    consensus: &ConsensusClient,

    subgrove_id: &str,
    key: &str,
    data: serde_json::Value,
    owner_did: &str,
    signing_key: &SigningKey,
    nonce: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    use ed25519_dalek::Signer;

    let data_json = serde_json::to_string(&data)?;
    let message = format!("{}:{}:{}", subgrove_id, key, data_json);

    let signature = signing_key.sign(message.as_bytes());

    let transaction = json!({
        "StoreData": {

            "subgrove_id": subgrove_id,
            "key": key,
            "data": data,
            "owner_did": owner_did,
            "signature": signature.to_bytes().to_vec(),
            "public_key_id": format!("{}#key-1", owner_did),
            "nonce": nonce
        }
    });

    submit_transaction(consensus, &transaction).await
}

// Helper function to submit transaction
async fn submit_transaction(
    _consensus: &ConsensusClient,
    transaction: &serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let tx_json = serde_json::to_string(transaction)?;
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

    let client = reqwest::Client::new();
    let response = client
        .post("http://localhost:26657")
        .json(&rpc_request)
        .send()
        .await?;

    let response_text = response.text().await?;
    let rpc_response: serde_json::Value = serde_json::from_str(&response_text)?;

    if let Some(error) = rpc_response.get("error") {
        return Err(format!("CometBFT error: {}", error).into());
    }

    if let Some(result) = rpc_response.get("result") {
        let code = result.get("code").and_then(|c| c.as_u64()).unwrap_or(0);
        if code != 0 {
            let log = result
                .get("log")
                .and_then(|l| l.as_str())
                .unwrap_or("Unknown error");
            return Err(format!("Transaction failed with code {}: {}", code, log).into());
        }

        Ok(result
            .get("hash")
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string())
    } else {
        Err("No result in response".into())
    }
}
