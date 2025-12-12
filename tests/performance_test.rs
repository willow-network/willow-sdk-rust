//! Performance test - measures indexing system performance

use willow_sdk::{WillowClient, ConsensusClient};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::fs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

const PRIVATE_KEY_HEX: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

#[tokio::test]
#[ignore] // Run with: cargo test performance_test -- --ignored --nocapture
async fn performance_test() {
    println!("⚡ Starting performance test...");
    println!("This test measures indexing system performance characteristics");

    // Read the funded DID
    let funded_did = fs::read_to_string("../../tools/app_registrar/app_owner_did.txt")
        .expect("Funded DID file not found")
        .trim()
        .to_string();

    // Generate unique subgrove name with timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let subgrove_name = format!("perf_test_{}", timestamp);

    println!("\n📋 Test Configuration:");
    println!("  DID: {}", funded_did);
    println!("  App: test_app");
    println!("  Subgrove: {}", subgrove_name);

    let client = WillowClient::new("http://localhost:3031").await.unwrap();
    let consensus = ConsensusClient::new("http://localhost:26657");

    let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("Invalid private key hex");
    let signing_key =
        SigningKey::from_bytes(&private_key_bytes.try_into().expect("Invalid key length"));

    // Setup: Wait for app and register subgrove optimized for performance testing
    println!("\n📝 Setup: Waiting for app and registering performance test subgrove...");

    // Wait for test_app to be registered
    let mut app_check_attempts = 0;
    let max_app_check_attempts = 30;
    let mut app_exists = false;

    println!("  ⏳ Checking if test_app exists...");
    while app_check_attempts < max_app_check_attempts {
        // Try to authenticate first
        match client
            .authenticate(
                &funded_did,
                PRIVATE_KEY_HEX,
                &format!("{}#key-1", funded_did),
            )
            .await
        {
            Ok(_) => {
                // Try to access the app by attempting to list subgroves or perform a simple operation
                match client
                    .data()
                    .query("test_app", "dummy_subgrove", json!({"filters": {}}))
                    .await
                {
                    Ok(_) => {
                        println!("  ✅ test_app exists and is accessible");
                        app_exists = true;
                        break;
                    }
                    Err(e) => {
                        if e.to_string().contains("App not found")
                            || e.to_string().contains("not registered")
                        {
                            app_check_attempts += 1;
                            if app_check_attempts < max_app_check_attempts {
                                println!(
                                    "  ⏳ App check attempt {} - app not found yet. Waiting 2s...",
                                    app_check_attempts
                                );
                                sleep(Duration::from_secs(2)).await;
                            }
                        } else {
                            // App exists but subgrove doesn't, which is expected
                            println!(
                                "  ✅ test_app exists (subgrove query returned expected error)"
                            );
                            app_exists = true;
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                app_check_attempts += 1;
                if app_check_attempts < max_app_check_attempts {
                    println!(
                        "  ⏳ App check attempt {} - authentication failed. Waiting 2s...",
                        app_check_attempts
                    );
                    sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    if !app_exists {
        panic!(
            "test_app not found after {} attempts. Make sure it's registered first.",
            max_app_check_attempts
        );
    }

    let schema = json!({
        "version": 1,
        "fields": {
            "id": "string",
            "type": "string",
            "timestamp": "number",
            "data": "string",
            "value": "number",
            "indexed_field": "string"
        },
        "indexes": [
            {
                "name": "by_type",
                "fields": ["type"],
                "unique": false
            },
            {
                "name": "by_timestamp",
                "fields": ["timestamp"],
                "unique": false
            }
        ],
        "required_fields": ["id", "type", "timestamp"]
    });

    let mut nonce = 3;
    let _ = register_subgrove(
        &consensus,
        &subgrove_name,
        &schema,
        &funded_did,
        &signing_key,
        nonce,
    )
    .await;
    nonce += 1;
    sleep(Duration::from_secs(10)).await;

    // Fund app with extra funds for performance test
    let _ = fund_app(&consensus, &funded_did).await;
    sleep(Duration::from_secs(10)).await;

    // Authenticate with retry logic
    let mut auth_attempts = 0;
    let max_auth_attempts = 30;
    let mut authenticated = false;

    println!("  ⏳ Authenticating...");
    while auth_attempts < max_auth_attempts {
        match client
            .authenticate(
                &funded_did,
                PRIVATE_KEY_HEX,
                &format!("{}#key-1", funded_did),
            )
            .await
        {
            Ok(_) => {
                println!(
                    "  ✅ Successfully authenticated after {} attempts",
                    auth_attempts + 1
                );
                authenticated = true;
                break;
            }
            Err(e) => {
                auth_attempts += 1;
                if auth_attempts < max_auth_attempts {
                    println!(
                        "  ⏳ Authentication attempt {} failed: {}. Retrying in 2s...",
                        auth_attempts, e
                    );
                    sleep(Duration::from_secs(2)).await;
                } else {
                    panic!(
                        "Failed to authenticate after {} attempts: {}",
                        max_auth_attempts, e
                    );
                }
            }
        }
    }

    if !authenticated {
        panic!("Failed to authenticate within timeout");
    }

    // Test 1: Sequential write performance
    println!("\n🧪 Test 1: Sequential Write Performance");
    println!("  Testing time to store documents sequentially...");

    let num_docs = 10;
    let mut write_times = Vec::new();

    for i in 0..num_docs {
        let doc_key = format!("perf_doc_{}", i);
        let doc_data = json!({
            "id": format!("doc_{}", i),
            "type": if i % 2 == 0 { "even" } else { "odd" },
            "timestamp": 1000 + i,
            "data": format!("Performance test document {} with some content to simulate real data", i),
            "value": i * 10,
            "indexed_field": format!("indexed_{}", i % 5)
        });

        let start = Instant::now();
        match store_data(
            &consensus,
            &subgrove_name,
            &doc_key,
            doc_data,
            &funded_did,
            &signing_key,
            nonce,
        )
        .await
        {
            Ok(_) => {
                let elapsed = start.elapsed();
                write_times.push(elapsed);
                println!("    Document {}: {:?}", i, elapsed);
            }
            Err(e) => println!("    ❌ Failed to store document {}: {}", i, e),
        }
        nonce += 1;

        // Small delay to prevent overwhelming the system
        sleep(Duration::from_millis(500)).await;
    }

    // Calculate write statistics
    if !write_times.is_empty() {
        let total_write_time: Duration = write_times.iter().sum();
        let avg_write_time = total_write_time / write_times.len() as u32;
        let min_write_time = write_times.iter().min().unwrap();
        let max_write_time = write_times.iter().max().unwrap();

        println!("\n  📊 Write Performance Summary:");
        println!("    Total documents: {}", num_docs);
        println!("    Average write time: {:?}", avg_write_time);
        println!("    Min write time: {:?}", min_write_time);
        println!("    Max write time: {:?}", max_write_time);
        println!("    Total time: {:?}", total_write_time);
    }

    // Wait for indexing
    println!("\n  ⏳ Waiting for indexing to complete...");
    sleep(Duration::from_secs(20)).await;

    // Test 2: Read performance
    println!("\n🧪 Test 2: Read Performance");
    println!("  Testing time to retrieve documents...");

    let mut read_times = Vec::new();

    for i in 0..num_docs {
        let doc_key = format!("perf_doc_{}", i);

        let start = Instant::now();
        match client
            .data()
            .get("test_app", &subgrove_name, &doc_key)
            .await
        {
            Ok(_) => {
                let elapsed = start.elapsed();
                read_times.push(elapsed);
                if i < 5 || i >= num_docs - 5 {
                    println!("    Document {}: {:?}", i, elapsed);
                }
            }
            Err(e) => println!("    ❌ Failed to read document {}: {}", i, e),
        }
    }

    // Calculate read statistics
    if !read_times.is_empty() {
        let total_read_time: Duration = read_times.iter().sum();
        let avg_read_time = total_read_time / read_times.len() as u32;
        let min_read_time = read_times.iter().min().unwrap();
        let max_read_time = read_times.iter().max().unwrap();

        println!("\n  📊 Read Performance Summary:");
        println!("    Total documents: {}", read_times.len());
        println!("    Average read time: {:?}", avg_read_time);
        println!("    Min read time: {:?}", min_read_time);
        println!("    Max read time: {:?}", max_read_time);
        println!("    Total time: {:?}", total_read_time);
    }

    // Test 3: Query performance
    println!("\n🧪 Test 3: Query Performance");
    println!("  Testing query response times...");

    // Query 1: Filter by type
    let start = Instant::now();
    match client
        .data()
        .query(
            "test_app",
            &subgrove_name,
            json!({
                "filters": { "type": "even" }
            }),
        )
        .await
    {
        Ok(results) => {
            let elapsed = start.elapsed();
            if results.documents.is_empty() && num_docs > 0 {
                panic!(
                    "❌ ERROR: Filter query returned 0 documents, but we stored {} even documents!",
                    num_docs / 2
                );
            }
            println!(
                "    Filter query (type=even): {:?} - returned {} docs",
                elapsed,
                results.documents.len()
            );
            if num_docs > 0 && results.documents.len() != (num_docs / 2) {
                println!(
                    "    ⚠️  WARNING: Expected {} even documents, but found {}",
                    num_docs / 2,
                    results.documents.len()
                );
            }
        }
        Err(e) => panic!("❌ Filter query failed: {}", e),
    }

    // Query 2: Sort by timestamp
    let start = Instant::now();
    match client
        .data()
        .query(
            "test_app",
            &subgrove_name,
            json!({
                "filters": {},
                "sort": { "field": "timestamp", "order": "desc" },
                "limit": 5
            }),
        )
        .await
    {
        Ok(results) => {
            let elapsed = start.elapsed();
            if results.documents.is_empty() && num_docs > 0 {
                panic!(
                    "❌ ERROR: Sort query returned 0 documents, but we stored {} documents!",
                    num_docs
                );
            }
            println!(
                "    Sort query (by timestamp): {:?} - returned {} docs",
                elapsed,
                results.documents.len()
            );
            let expected_docs = std::cmp::min(5, num_docs);
            if results.documents.len() != expected_docs {
                println!(
                    "    ⚠️  WARNING: Expected {} documents (limited to 5), but found {}",
                    expected_docs,
                    results.documents.len()
                );
            }
        }
        Err(e) => panic!("❌ Sort query failed: {}", e),
    }

    // Query 3: Pagination
    let start = Instant::now();
    match client
        .data()
        .query(
            "test_app",
            &subgrove_name,
            json!({
                "filters": {},
                "limit": 3,
                "offset": 0
            }),
        )
        .await
    {
        Ok(results) => {
            let elapsed = start.elapsed();
            if results.documents.is_empty() && num_docs > 0 {
                panic!(
                    "❌ ERROR: Pagination query returned 0 documents, but we stored {} documents!",
                    num_docs
                );
            }
            println!(
                "    Pagination query (limit=3): {:?} - returned {} docs",
                elapsed,
                results.documents.len()
            );
            let expected_docs = std::cmp::min(3, num_docs);
            if results.documents.len() != expected_docs {
                println!(
                    "    ⚠️  WARNING: Expected {} documents (limited to 3), but found {}",
                    expected_docs,
                    results.documents.len()
                );
            }
        }
        Err(e) => panic!("❌ Pagination query failed: {}", e),
    }

    // Test 4: Concurrent read performance
    println!("\n🧪 Test 4: Concurrent Read Performance");
    println!("  Testing parallel read operations...");

    use tokio::task::JoinSet;

    let concurrent_reads = 5;
    let mut tasks = JoinSet::new();

    let start = Instant::now();

    for i in 0..concurrent_reads {
        let client_clone = client.clone();
        let doc_key = format!("perf_doc_{}", i);
        let subgrove_name_clone = subgrove_name.clone();

        tasks.spawn(async move {
            let task_start = Instant::now();
            let result = client_clone
                .data()
                .get("test_app", &subgrove_name_clone, &doc_key)
                .await;
            (i, result, task_start.elapsed())
        });
    }

    let mut concurrent_results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok((i, read_result, duration)) = result {
            concurrent_results.push((i, read_result.is_ok(), duration));
        }
    }

    let total_concurrent_time = start.elapsed();

    println!(
        "    Total time for {} concurrent reads: {:?}",
        concurrent_reads, total_concurrent_time
    );
    for (i, success, duration) in &concurrent_results {
        println!(
            "      Read {}: {} ({:?})",
            i,
            if *success { "✅" } else { "❌" },
            duration
        );
    }

    // Test 5: Transaction timing requirements
    println!("\n🧪 Test 5: Transaction Timing Requirements");
    println!("  Testing minimum delays between transactions...");

    // Test rapid sequential transactions
    let test_delays = vec![0, 500, 1000, 2000];

    for delay_ms in test_delays {
        let doc_key = format!("timing_test_{}", delay_ms);
        let doc_data = json!({
            "id": format!("timing_{}", delay_ms),
            "type": "timing_test",
            "timestamp": 9000 + delay_ms,
            "data": format!("Testing {}ms delay", delay_ms)
        });

        println!("\n    Testing {}ms delay between transactions:", delay_ms);

        // Store
        let store_start = Instant::now();
        match store_data(
            &consensus,
            &subgrove_name,
            &doc_key,
            doc_data,
            &funded_did,
            &signing_key,
            nonce,
        )
        .await
        {
            Ok(_) => println!("      Store: ✅ ({:?})", store_start.elapsed()),
            Err(e) => println!("      Store: ❌ {} ({:?})", e, store_start.elapsed()),
        }
        nonce += 1;

        // Wait specified delay
        sleep(Duration::from_millis(delay_ms)).await;

        // Try immediate read
        let read_start = Instant::now();
        match client
            .data()
            .get("test_app", &subgrove_name, &doc_key)
            .await
        {
            Ok(_) => println!("      Immediate read: ✅ ({:?})", read_start.elapsed()),
            Err(_) => {
                println!("      Immediate read: ❌ ({:?})", read_start.elapsed());

                // Try again after standard delay
                sleep(Duration::from_secs(15)).await;
                match client
                    .data()
                    .get("test_app", &subgrove_name, &doc_key)
                    .await
                {
                    Ok(_) => println!("      Delayed read: ✅"),
                    Err(_) => println!("      Delayed read: ❌"),
                }
            }
        }
    }

    // Summary
    println!("\n📊 Performance Test Summary:");
    println!(
        "  - Sequential writes: ~{:?} per document",
        write_times.iter().sum::<Duration>() / write_times.len() as u32
    );
    println!(
        "  - Sequential reads: ~{:?} per document",
        read_times.iter().sum::<Duration>() / read_times.len() as u32
    );
    println!(
        "  - Concurrent read speedup: {:.2}x",
        (read_times
            .iter()
            .take(concurrent_reads)
            .sum::<Duration>()
            .as_millis() as f64)
            / (total_concurrent_time.as_millis() as f64)
    );
    println!("  - Recommended minimum transaction delay: 15 seconds for guaranteed indexing");

    println!("\n✅ Performance test completed!");
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
        "RegisterSubgrove\nID: {}\nApp: test_app\nName: Performance Test\nSchemaHash: {}\nOwner: {}\nWriters: \nReaders: \nNonce: {}",
        subgrove_id, schema_hash_hex, owner_did, nonce
    );

    let signature = signing_key.sign(message.as_bytes());

    let transaction = json!({
        "RegisterSubgrove": {
            "subgrove_id": subgrove_id,
            "app_id": "test_app",
            "name": "Performance Test",
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

async fn fund_app(
    consensus: &ConsensusClient,
    from_did: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let fund_tx = json!({
        "FundApp": {
            "app_id": "test_app",
            "amount": "20000000000000000000", // 20 CAN for performance test
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
    let message = format!("test_app:{}:{}:{}", subgrove_id, key, data_json);
    let signature = signing_key.sign(message.as_bytes());

    let transaction = json!({
        "StoreData": {
            "app_id": "test_app",
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
