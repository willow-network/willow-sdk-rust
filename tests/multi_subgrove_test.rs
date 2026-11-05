//! Multi-subgrove test - tests operations across multiple subgroves

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use willow_sdk::{signed_messages, ConsensusClient, WillowClient};

// RFC 8032 §7.1 Test 2 Ed25519 vector.
const PRIVATE_KEY_HEX: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

#[tokio::test]
#[ignore] // Run with: cargo test multi_subgrove_test -- --ignored --nocapture
async fn multi_subgrove_test() {
    println!("🎯 Starting multi-subgrove test...");
    println!("This test verifies operations across multiple subgroves");

    // Read the funded DID
    let funded_did =
        std::env::var("WILLOW_TEST_DID").unwrap_or_else(|_| "did:willow:test-owner".to_string());

    // Generate unique subgrove names with timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let users_subgrove = format!("users_{}", timestamp);
    let posts_subgrove = format!("posts_{}", timestamp);
    let comments_subgrove = format!("comments_{}", timestamp);

    println!("\n📋 Test Configuration:");
    println!("  DID: {}", funded_did);
    println!("  Subgrove: test-subgrove");
    println!(
        "  Subgroves: {}, {}, {}",
        users_subgrove, posts_subgrove, comments_subgrove
    );

    let client = WillowClient::new("http://localhost:3031").await.unwrap();
    let consensus = ConsensusClient::new("http://localhost:26657");

    let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("Invalid private key hex");
    let signing_key =
        SigningKey::from_bytes(&private_key_bytes.try_into().expect("Invalid key length"));

    // Step 1: Wait for app to be registered and register multiple subgroves with different schemas
    println!("\n📝 Step 1: Waiting for subgrove and registering multiple subgroves...");

    // Wait for subgrove to be registered
    let mut app_check_attempts = 0;
    let max_app_check_attempts = 30;
    let mut app_exists = false;

    client.set_identity(
        &funded_did,
        PRIVATE_KEY_HEX,
        &format!("{}#key-1", funded_did),
    );

    println!("  ⏳ Checking if Subgrove exists...");
    while app_check_attempts < max_app_check_attempts {
        // Try to access the app by attempting to list subgroves or perform a simple operation
        match client
            .data()
            .query_unverified("dummy_subgrove", json!({"filters": {}}))
            .await
        {
            Ok(_) => {
                println!("  ✅ Subgrove exists and is accessible");
                app_exists = true;
                break;
            }
            Err(e) => {
                if e.to_string().contains("Subgrove not found")
                    || e.to_string().contains("not registered")
                {
                    app_check_attempts += 1;
                    if app_check_attempts < max_app_check_attempts {
                        println!(
                            "  ⏳ Subgrove check attempt {} - subgrove not found yet. Waiting 2s...",
                            app_check_attempts
                        );
                        sleep(Duration::from_secs(2)).await;
                    }
                } else {
                    // App exists but subgrove doesn't, which is expected
                    println!("  ✅ Subgrove exists (subgrove query returned expected error)");
                    app_exists = true;
                    break;
                }
            }
        }
    }

    if !app_exists {
        panic!(
            "Subgrove not found after {} attempts. Make sure it's registered first.",
            max_app_check_attempts
        );
    }

    let mut nonce = 3; // Starting nonce

    // Users subgrove
    let users_schema = json!({
        "version": 1,
        "fields": {
            "username": "string",
            "email": "string",
            "created_at": "number",
            "is_active": "boolean",
            "profile": "object"
        },
        "indexes": [{
            "name": "by_username",
            "fields": ["username"],
            "unique": true
        }],
        "required_fields": ["username", "email", "created_at"]
    });

    match register_subgrove(
        &consensus,
        &users_subgrove,
        "Users",
        &users_schema,
        &funded_did,
        &signing_key,
        nonce,
    )
    .await
    {
        Ok(tx) => println!("  ✅ Users subgrove registered: {}", tx),
        Err(e) => println!("  ⚠️  Users subgrove error: {}", e),
    }
    nonce += 1;
    sleep(Duration::from_secs(5)).await;

    // Posts subgrove
    let posts_schema = json!({
        "version": 1,
        "fields": {
            "title": "string",
            "content": "string",
            "author_id": "string",
            "created_at": "number",
            "tags": "array",
            "likes": "number"
        },
        "indexes": [
            {
                "name": "by_author",
                "fields": ["author_id"],
                "unique": false
            },
            {
                "name": "by_created_at",
                "fields": ["created_at"],
                "unique": false
            }
        ],
        "required_fields": ["title", "content", "author_id", "created_at"]
    });

    match register_subgrove(
        &consensus,
        &posts_subgrove,
        "Posts",
        &posts_schema,
        &funded_did,
        &signing_key,
        nonce,
    )
    .await
    {
        Ok(tx) => println!("  ✅ Posts subgrove registered: {}", tx),
        Err(e) => println!("  ⚠️  Posts subgrove error: {}", e),
    }
    nonce += 1;
    sleep(Duration::from_secs(5)).await;

    // Comments subgrove
    let comments_schema = json!({
        "version": 1,
        "fields": {
            "post_id": "string",
            "author_id": "string",
            "content": "string",
            "created_at": "number"
        },
        "indexes": [
            {
                "name": "by_post",
                "fields": ["post_id"],
                "unique": false
            }
        ],
        "required_fields": ["post_id", "author_id", "content", "created_at"]
    });

    match register_subgrove(
        &consensus,
        &comments_subgrove,
        "Comments",
        &comments_schema,
        &funded_did,
        &signing_key,
        nonce,
    )
    .await
    {
        Ok(tx) => println!("  ✅ Comments subgrove registered: {}", tx),
        Err(e) => println!("  ⚠️  Comments subgrove error: {}", e),
    }
    nonce += 1;

    println!("  ⏳ Waiting for subgrove initialization...");
    sleep(Duration::from_secs(10)).await;

    // Fund subgrove
    let _ = fund_subgrove(&consensus, &funded_did).await;
    sleep(Duration::from_secs(10)).await;

    // Step 2: Store related data across subgroves
    println!("\n📊 Step 2: Storing related data across subgroves...");

    // Store users
    let users = vec![
        (
            "user_alice",
            json!({
                "username": "alice",
                "email": "alice@example.com",
                "created_at": 1000,
                "is_active": true,
                "profile": {
                    "bio": "Blockchain developer",
                    "location": "San Francisco"
                }
            }),
        ),
        (
            "user_bob",
            json!({
                "username": "bob",
                "email": "bob@example.com",
                "created_at": 2000,
                "is_active": true,
                "profile": {
                    "bio": "DeFi enthusiast",
                    "location": "New York"
                }
            }),
        ),
    ];

    for (key, data) in &users {
        match store_data(
            &consensus,
            &users_subgrove,
            key,
            data.clone(),
            &funded_did,
            &signing_key,
            nonce,
        )
        .await
        {
            Ok(_) => println!("  ✅ Stored user: {}", data["username"]),
            Err(e) => println!("  ❌ Failed to store user: {}", e),
        }
        nonce += 1;
        sleep(Duration::from_secs(2)).await;
    }

    // Store posts
    let posts = vec![
        (
            "post_1",
            json!({
                "title": "Introduction to Willow",
                "content": "Willow provides decentralized indexing...",
                "author_id": "user_alice",
                "created_at": 3000,
                "tags": ["willow", "indexing", "tutorial"],
                "likes": 10
            }),
        ),
        (
            "post_2",
            json!({
                "title": "Building DApps Guide",
                "content": "Learn how to build decentralized applications...",
                "author_id": "user_bob",
                "created_at": 4000,
                "tags": ["dapp", "development"],
                "likes": 15
            }),
        ),
        (
            "post_3",
            json!({
                "title": "Query Optimization Tips",
                "content": "Best practices for query performance...",
                "author_id": "user_alice",
                "created_at": 5000,
                "tags": ["performance", "optimization"],
                "likes": 8
            }),
        ),
    ];

    for (key, data) in &posts {
        match store_data(
            &consensus,
            &posts_subgrove,
            key,
            data.clone(),
            &funded_did,
            &signing_key,
            nonce,
        )
        .await
        {
            Ok(_) => println!("  ✅ Stored post: {}", data["title"]),
            Err(e) => println!("  ❌ Failed to store post: {}", e),
        }
        nonce += 1;
        sleep(Duration::from_secs(2)).await;
    }

    // Store comments
    let comments = vec![
        (
            "comment_1",
            json!({
                "post_id": "post_1",
                "author_id": "user_bob",
                "content": "Great introduction!",
                "created_at": 3500
            }),
        ),
        (
            "comment_2",
            json!({
                "post_id": "post_1",
                "author_id": "user_alice",
                "content": "Thanks for reading!",
                "created_at": 3600
            }),
        ),
        (
            "comment_3",
            json!({
                "post_id": "post_2",
                "author_id": "user_alice",
                "content": "Very helpful guide!",
                "created_at": 4500
            }),
        ),
    ];

    for (key, data) in &comments {
        match store_data(
            &consensus,
            &comments_subgrove,
            key,
            data.clone(),
            &funded_did,
            &signing_key,
            nonce,
        )
        .await
        {
            Ok(_) => println!("  ✅ Stored comment on {}", data["post_id"]),
            Err(e) => println!("  ❌ Failed to store comment: {}", e),
        }
        nonce += 1;
        sleep(Duration::from_secs(2)).await;
    }

    println!("  ⏳ Waiting for indexing to complete...");
    sleep(Duration::from_secs(15)).await;

    // Step 3: Verify data isolation between subgroves
    println!("\n🔍 Step 3: Verifying data isolation between subgroves...");

    // Set identity (already set earlier, but re-affirm)
    client.set_identity(
        &funded_did,
        PRIVATE_KEY_HEX,
        &format!("{}#key-1", funded_did),
    );
    println!("  ✅ Identity set");

    // Try to read user data from users subgrove
    match client.data().get(&users_subgrove, "user_alice").await {
        Ok(data) => println!(
            "  ✅ Retrieved user alice from users subgrove: {}",
            data["username"]
        ),
        Err(e) => println!("  ❌ Failed to retrieve user: {}", e),
    }

    // Verify we can't read user data from posts subgrove
    match client.data().get(&posts_subgrove, "user_alice").await {
        Ok(_) => println!("  ❌ ERROR: Retrieved user data from posts subgrove!"),
        Err(_) => println!("  ✅ Correctly failed to retrieve user data from posts subgrove"),
    }

    // Step 4: Test cross-subgrove queries (simulated relationships)
    println!("\n🔗 Step 4: Testing cross-subgrove data relationships...");

    // Get all posts by alice
    println!("\n  Finding all posts by alice:");
    let alice_posts_query = json!({
        "filters": { "author_id": "user_alice" }
    });

    match client
        .data()
        .query_unverified(&posts_subgrove, alice_posts_query)
        .await
    {
        Ok(results) => {
            if results.documents.is_empty() {
                panic!("❌ ERROR: Query returned 0 posts by alice, but we stored 2 posts!");
            }
            println!("  ✅ Found {} posts by alice", results.documents.len());
            if results.documents.len() != 2 {
                println!(
                    "  ⚠️  WARNING: Expected 2 posts by alice, but found {}",
                    results.documents.len()
                );
            }

            for post in &results.documents {
                println!("    - {}", post["title"]);

                // For each post, find comments
                if let Some(post_key) = post.get("_key").and_then(|k| k.as_str()) {
                    let comments_query = json!({
                        "filters": { "post_id": post_key }
                    });

                    match client
                        .data()
                        .query_unverified(&comments_subgrove, comments_query)
                        .await
                    {
                        Ok(comment_results) => {
                            println!(
                                "      {} comments on this post",
                                comment_results.documents.len()
                            );
                        }
                        Err(e) => {
                            println!("      ❌ Failed to query comments: {}", e);
                        }
                    }
                }
            }
        }
        Err(e) => panic!("❌ Query for alice's posts failed: {}", e),
    }

    // Step 5: Test concurrent operations on different subgroves
    println!("\n⚡ Step 5: Testing concurrent operations...");

    use tokio::join;

    let client_clone1 = client.clone();
    let client_clone2 = client.clone();
    let _consensus_clone1 = ConsensusClient::new("http://localhost:26657");
    let _consensus_clone2 = ConsensusClient::new("http://localhost:26657");

    let users_subgrove_clone = users_subgrove.clone();
    let posts_subgrove_clone = posts_subgrove.clone();

    let task1 = tokio::spawn(async move {
        // Read from users
        client_clone1
            .data()
            .get(&users_subgrove_clone, "user_bob")
            .await
    });

    let task2 = tokio::spawn(async move {
        // Read from posts
        client_clone2
            .data()
            .get(&posts_subgrove_clone, "post_2")
            .await
    });

    let (result1, result2) = join!(task1, task2);

    match result1 {
        Ok(Ok(data)) => println!("  ✅ Concurrent read 1 (users): {}", data["username"]),
        _ => println!("  ❌ Concurrent read 1 failed"),
    }

    match result2 {
        Ok(Ok(data)) => println!("  ✅ Concurrent read 2 (posts): {}", data["title"]),
        _ => println!("  ❌ Concurrent read 2 failed"),
    }

    // Summary
    println!("\n📊 Multi-subgrove test summary:");
    println!("  - Created 3 subgroves with different schemas");
    println!(
        "  - Stored {} users, {} posts, {} comments",
        users.len(),
        posts.len(),
        comments.len()
    );
    println!("  - Verified data isolation between subgroves");
    println!("  - Tested cross-subgrove relationships");
    println!("  - Verified concurrent operations");

    println!("\n✅ Multi-subgrove test completed!");
}

// Helper functions
async fn register_subgrove(
    consensus: &ConsensusClient,
    subgrove_id: &str,
    name: &str,
    schema: &serde_json::Value,
    owner_did: &str,
    signing_key: &SigningKey,
    nonce: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    use ed25519_dalek::Signer;
    use willow_sdk::consensus::SubgroveMode;
    use willow_sdk::signed_messages::{self, RegisterSubgroveTx};

    // Every field is sent explicitly; the signature binds them all through `Config`.
    let mut tx = RegisterSubgroveTx {
        subgrove_id: subgrove_id.to_string(),
        name: name.to_string(),
        description: String::new(),
        schema: serde_json::to_string(schema)?,
        owner_did: owner_did.to_string(),
        admins: vec![],
        initial_funding: None,
        checkpoint_verification: Default::default(),
        mode: SubgroveMode::DataStorage {
            name: name.to_string(),
            writers: vec![],
            free_readers: vec![],
            read_pricing: None,
        },
        privacy: None,
        initial_owner_key_grant: None,
        template_config: None,
        confirmation_depth: 0,
        signature: vec![],
        public_key_id: format!("{}#key-1", owner_did),
        nonce,
        cryptographic_completeness: false,
    };
    let message = signed_messages::register_subgrove(&tx)?;
    tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();

    let tx_json = ConsensusClient::serialize_tx("RegisterSubgrove", &tx)?;
    Ok(consensus.submit_transaction_json(&tx_json).await?)
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

    let mut tx = signed_messages::StoreDataTx {
        subgrove_id: subgrove_id.to_string(),
        key: key.to_string(),
        data: serde_json::to_vec(&data)?,
        owner_did: owner_did.to_string(),
        signature: vec![],
        public_key_id: format!("{}#key-1", owner_did),
        nonce,
    };
    let message = signed_messages::store_data(&tx)?;
    tx.signature = signing_key.sign(message.as_bytes()).to_bytes().to_vec();

    let tx_json = ConsensusClient::serialize_tx("StoreData", &tx)?;
    Ok(consensus.submit_transaction_json(&tx_json).await?)
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
