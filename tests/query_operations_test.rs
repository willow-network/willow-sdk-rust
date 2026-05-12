//! Query operations test - tests current query capabilities

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use willow_sdk::{ConsensusClient, WillowClient};

const PRIVATE_KEY_HEX: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

#[tokio::test]
#[ignore] // Run with: cargo test query_operations_test -- --ignored --nocapture
async fn query_operations_test() {
    println!("🔍 Starting query operations test...");
    println!("This test verifies current query capabilities");

    // Read the funded DID
    let funded_did =
        std::env::var("WILLOW_TEST_DID").unwrap_or_else(|_| "did:willow:test-owner".to_string());

    // Generate unique subgrove name with timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let subgrove_name = format!("query_products_{}", timestamp);

    println!("\n📋 Test Configuration:");
    println!("  DID: {}", funded_did);
    println!("  Subgrove: test-subgrove");
    println!("  Subgrove: {}", subgrove_name);

    let client = WillowClient::new("http://localhost:3031").await.unwrap();
    let consensus = ConsensusClient::new("http://localhost:26657");

    let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("Invalid private key hex");
    let signing_key =
        SigningKey::from_bytes(&private_key_bytes.try_into().expect("Invalid key length"));

    // Setup: Register subgrove
    println!("\n📝 Setup: Registering products subgrove...");

    let schema = json!({
        "version": 1,
        "fields": {
            "name": "string",
            "category": "string",
            "price": "number",
            "in_stock": "boolean",
            "tags": "array",
            "rating": "number"
        },
        "indexes": [
            {
                "name": "by_category",
                "fields": ["category"],
                "unique": false
            },
            {
                "name": "by_price",
                "fields": ["price"],
                "unique": false
            }
        ],
        "required_fields": ["name", "category", "price", "in_stock"]
    });

    // Check if Subgrove exists, wait for it if network just restarted
    println!("  ⏳ Checking for subgrove...");
    let mut app_exists = false;
    for attempt in 1..=30 {
        // Try to register subgrove - if app doesn't exist, it will fail
        match register_subgrove(
            &consensus,
            &subgrove_name,
            &schema,
            &funded_did,
            &signing_key,
            3,
        )
        .await
        {
            Ok(_) => {
                println!("  ✅ Subgrove registered successfully");
                app_exists = true;
                break;
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("Subgrove not found")
                    || error_str.contains("subgrove does not exist")
                {
                    if attempt == 1 || attempt % 5 == 0 {
                        println!(
                            "  ⏳ Waiting for subgrove to be registered... (attempt {}/30)",
                            attempt
                        );
                    }
                    sleep(Duration::from_secs(2)).await;
                } else {
                    // Different error - maybe subgrove already exists or other issue
                    println!("  ⚠️  Subgrove registration error: {}", error_str);
                    break;
                }
            }
        }
    }

    if !app_exists {
        panic!("Subgrove was not registered after network restart. Please ensure start_three_nodes_with_funding.sh completes successfully.");
    }

    sleep(Duration::from_secs(10)).await;

    // Fund subgrove
    let _ = fund_subgrove(&consensus, &funded_did).await;
    sleep(Duration::from_secs(10)).await;

    // Store test products
    println!("\n📊 Storing test products...");

    let products = vec![
        (
            "laptop_1",
            json!({
                "name": "Gaming Laptop Pro",
                "category": "electronics",
                "price": 1299.99,
                "in_stock": true,
                "tags": ["gaming", "laptop", "high-performance"],
                "rating": 4.5
            }),
        ),
        (
            "laptop_2",
            json!({
                "name": "Business Laptop",
                "category": "electronics",
                "price": 899.99,
                "in_stock": true,
                "tags": ["business", "laptop", "productivity"],
                "rating": 4.2
            }),
        ),
        (
            "book_1",
            json!({
                "name": "Blockchain Fundamentals",
                "category": "books",
                "price": 29.99,
                "in_stock": true,
                "tags": ["blockchain", "technology", "educational"],
                "rating": 4.8
            }),
        ),
        (
            "book_2",
            json!({
                "name": "DeFi Guide",
                "category": "books",
                "price": 34.99,
                "in_stock": false,
                "tags": ["defi", "finance", "crypto"],
                "rating": 4.6
            }),
        ),
        (
            "accessory_1",
            json!({
                "name": "USB-C Hub",
                "category": "accessories",
                "price": 49.99,
                "in_stock": true,
                "tags": ["usb", "hub", "connectivity"],
                "rating": 4.0
            }),
        ),
    ];

    let mut nonce = 4;
    for (key, data) in &products {
        let _ = store_data(
            &consensus,
            &subgrove_name,
            key,
            data.clone(),
            &funded_did,
            &signing_key,
            nonce,
        )
        .await;
        nonce += 1;
        sleep(Duration::from_secs(2)).await;
    }

    println!("  ⏳ Waiting for indexing...");
    sleep(Duration::from_secs(15)).await;

    // Wait for DID and app to be registered (network may have just restarted)
    println!("\n⏳ Waiting for network to be ready...");
    println!("  (The test runner may have restarted the network)");

    client.set_identity(
        &funded_did,
        PRIVATE_KEY_HEX,
        &format!("{}#key-1", funded_did),
    );
    println!("  ✅ Identity set");

    // Test 1: Simple filter query
    println!("\n🧪 Test 1: Simple filter query (category = 'electronics')");

    let query = json!({
        "filters": { "category": "electronics" }
    });

    match client.data().query(&subgrove_name, query).await {
        Ok(results) => {
            println!("  ✅ Query returned {} documents", results.documents.len());
            for doc in &results.documents {
                println!(
                    "    - {} (${}) - in stock: {}",
                    doc["name"].as_str().unwrap_or(""),
                    doc["price"].as_f64().unwrap_or(0.0),
                    doc["in_stock"].as_bool().unwrap_or(false)
                );
            }
        }
        Err(e) => println!("  ❌ Query failed: {}", e),
    }

    // Test 1b: Query with proof
    println!("\n🧪 Test 1b: Query with cryptographic proof");

    let query_with_proof = json!({
        "filters": { "category": "electronics" },
        "include_proof": true
    });

    match client.data().query(&subgrove_name, query_with_proof).await {
        Ok(results) => {
            println!("  ✅ Query returned {} documents", results.documents.len());

            // Check if proof was included
            if let Some(proof) = &results.proof {
                println!("  📄 Proof included: {} bytes", proof.len() / 2);

                // Verify the proof and compute root hash
                use willow_sdk::QueryResponseExt;
                match results.verify_proof() {
                    Ok(computed_root_hash) => {
                        println!("  🔐 Computed root hash: {}", &computed_root_hash[..16]);

                        // Get the on-chain root hash
                        match client.get_root_hash().await {
                            Ok(node_root_hash) => {
                                println!("  🌐 Node root hash: {}", &node_root_hash[..16]);

                                // In production, you would get this from the blockchain
                                // For now, we just compare with what the node reports
                                if computed_root_hash == node_root_hash {
                                    println!("  ✅ Root hash matches!");
                                } else {
                                    println!("  ❌ Root hash mismatch!");
                                }
                            }
                            Err(e) => println!("  ⚠️  Failed to get node root hash: {}", e),
                        }
                    }
                    Err(e) => println!("  ⚠️  Proof verification error: {}", e),
                }
            } else {
                println!("  ⚠️  No proof included in response");
            }
        }
        Err(e) => println!("  ❌ Query failed: {}", e),
    }

    // Test 2: Query with sorting
    println!("\n🧪 Test 2: Query with sorting by price");

    let query = json!({
        "filters": {},
        "sort": { "field": "price", "order": "asc" }
    });

    match client.data().query(&subgrove_name, query).await {
        Ok(results) => {
            println!(
                "  ✅ Query returned {} documents sorted by price",
                results.documents.len()
            );
            for doc in &results.documents {
                println!(
                    "    - {} (${})",
                    doc["name"].as_str().unwrap_or(""),
                    doc["price"].as_f64().unwrap_or(0.0)
                );
            }
        }
        Err(e) => println!("  ❌ Query failed: {}", e),
    }

    // Test 3: Query with pagination
    println!("\n🧪 Test 3: Query with pagination (limit=2, offset=0)");

    let query = json!({
        "filters": {},
        "limit": 2,
        "offset": 0
    });

    match client.data().query(&subgrove_name, query).await {
        Ok(results) => {
            println!(
                "  ✅ Query returned {} documents (page 1)",
                results.documents.len()
            );
            for doc in &results.documents {
                println!("    - {}", doc["name"].as_str().unwrap_or(""));
            }

            // Page 2
            println!("\n  Testing page 2 (offset=2)...");
            let query_page2 = json!({
                "filters": {},
                "limit": 2,
                "offset": 2
            });

            if let Ok(results2) = client.data().query(&subgrove_name, query_page2).await {
                println!(
                    "  ✅ Page 2 returned {} documents",
                    results2.documents.len()
                );
                for doc in &results2.documents {
                    println!("    - {}", doc["name"].as_str().unwrap_or(""));
                }
            }
        }
        Err(e) => println!("  ❌ Query failed: {}", e),
    }

    // Test 4: Combined query (filter + sort + pagination)
    println!("\n🧪 Test 4: Combined query (in_stock=true, sorted by rating, limit 3)");

    let query = json!({
        "filters": { "in_stock": true },
        "sort": { "field": "rating", "order": "desc" },
        "limit": 3
    });

    match client.data().query(&subgrove_name, query).await {
        Ok(results) => {
            println!(
                "  ✅ Query returned {} in-stock products sorted by rating",
                results.documents.len()
            );
            for doc in &results.documents {
                println!(
                    "    - {} (rating: {}) - ${}",
                    doc["name"].as_str().unwrap_or(""),
                    doc["rating"].as_f64().unwrap_or(0.0),
                    doc["price"].as_f64().unwrap_or(0.0)
                );
            }
        }
        Err(e) => println!("  ❌ Query failed: {}", e),
    }

    // Test 5: Edge cases
    println!("\n🧪 Test 5: Query edge cases");

    // Empty result set
    println!("\n  5a. Query for non-existent category:");
    let query = json!({
        "filters": { "category": "nonexistent" }
    });

    match client.data().query(&subgrove_name, query).await {
        Ok(results) => println!(
            "    ✅ Empty query returned {} documents",
            results.documents.len()
        ),
        Err(e) => println!("    ❌ Query failed: {}", e),
    }

    // Large limit
    println!("\n  5b. Query with large limit:");
    let query = json!({
        "filters": {},
        "limit": 1000
    });

    match client.data().query(&subgrove_name, query).await {
        Ok(results) => println!(
            "    ✅ Large limit query returned {} documents",
            results.documents.len()
        ),
        Err(e) => println!("    ❌ Query failed: {}", e),
    }

    // Offset beyond data
    println!("\n  5c. Query with offset beyond available data:");
    let query = json!({
        "filters": {},
        "offset": 100
    });

    match client.data().query(&subgrove_name, query).await {
        Ok(results) => println!(
            "    ✅ High offset query returned {} documents",
            results.documents.len()
        ),
        Err(e) => println!("    ❌ Query failed: {}", e),
    }

    println!("\n✅ Query operations test completed!");
}

// Helper functions
async fn register_subgrove(
    consensus: &ConsensusClient,
    subgrove_id: &str,
    schema: &serde_json::Value,
    owner_did: &str,
    signing_key: &SigningKey,
    nonce: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    use ed25519_dalek::Signer;
    use sha3::{Digest, Keccak256};

    let schema_json = serde_json::to_string(schema)?;
    let mut hasher = Keccak256::new();
    hasher.update(schema_json.as_bytes());
    let schema_hash = hasher.finalize();
    let schema_hash_hex = hex::encode(schema_hash);

    let message = format!(
        "RegisterSubgrove\nID: {}\nName: Query Products\nSchemaHash: {}\nOwner: {}\nWriters: \nReaders: \nNonce: {}",
        subgrove_id, schema_hash_hex, owner_did, nonce
    );

    let signature = signing_key.sign(message.as_bytes());

    let transaction = json!({
        "RegisterSubgrove": {
            "subgrove_id": subgrove_id,

            "name": "Query Products",
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

async fn fund_subgrove(
    consensus: &ConsensusClient,
    from_did: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let fund_tx = json!({
        "FundSubgrove": {

            "amount": 10_000_000_000_000_000_000u128,
            "from_did": from_did,
            "signature": []
        }
    });

    submit_transaction(consensus, &fund_tx).await
}

async fn store_data(
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

    if let Some(result) = rpc_response.get("result") {
        Ok(result
            .get("hash")
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string())
    } else {
        Err("No result in response".into())
    }
}
