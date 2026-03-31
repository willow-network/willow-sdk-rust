//! Integration tests for automatic proof verification

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::collections::HashMap;
use willow_sdk::{
    auth::generate_did,
    types::{
        DidInfo, FieldType, RegisterSubgroveRequest, SchemaDefinition, SignatureAlgorithm,
        StoreDataRequest,
    },
    ConsensusClient, WillowClient, WillowError,
};

async fn setup_test_environment(
) -> Result<(WillowClient, ConsensusClient, DidInfo, SigningKey, String, String), Box<dyn std::error::Error>> {
    // Initialize clients
    let client = WillowClient::new("http://localhost:3031").await?;
    let consensus_client = ConsensusClient::new("http://localhost:26657");

    // Generate test DID
    let did_info = generate_did(SignatureAlgorithm::Ed25519)?;

    // Register DID via consensus
    let tx_hash = consensus_client
        .register_did(
            &did_info.did_document,
            &did_info.private_key_hex(),
            &did_info.public_key_id,
            SignatureAlgorithm::Ed25519,
            1,
        )
        .await?;

    // Wait for transaction
    consensus_client.wait_for_transaction(&tx_hash, 10).await?;

    // Set identity
    client.set_identity(
        &did_info.did,
        &did_info.private_key_hex(),
        &did_info.public_key_id,
    );

    // Create unique app and subgrove IDs
    let app_id = format!(
        "test-app-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let subgrove_id = "test-subgrove";

    // Register app
    let private_key_bytes =
        hex::decode(&did_info.private_key_hex()).expect("Invalid private key hex");
    let signing_key =
        SigningKey::from_bytes(&private_key_bytes.try_into().expect("Invalid key length"));
    consensus_client
        .register_app(
            &app_id,
            "Test App",
            "App for testing proof verification",
            "test",
            &did_info.did,
            vec![did_info.did.clone()],
            &did_info.private_key_hex(),
            &did_info.public_key_id,
            SignatureAlgorithm::Ed25519,
            2,
            None,
        )
        .await?;

    // Register subgrove
    let mut fields = std::collections::BTreeMap::new();
    fields.insert("id".to_string(), FieldType::String);
    fields.insert("value".to_string(), FieldType::Number);

    let subgrove_request = RegisterSubgroveRequest {
        subgrove_id: subgrove_id.to_string(),
        app_id: app_id.clone(),
        name: "Test Subgrove".to_string(),
        schema: Some(SchemaDefinition {
            version: 1,
            fields,
            required_fields: vec![],
            indexes: vec![],
        }),
        owner_did: did_info.did.clone(),
        writers: vec![did_info.did.clone()],
        readers: vec![did_info.did.clone()],
        signature: vec![],
        public_key_id: did_info.public_key_id.clone(),
        nonce: 3,
    };

    consensus_client
        .register_subgrove(subgrove_request, &signing_key)
        .await?;

    // Wait for registrations to be processed
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    Ok((
        client,
        consensus_client,
        did_info,
        signing_key,
        app_id,
        subgrove_id.to_string(),
    ))
}

/// Store data via consensus transaction (the correct write path)
async fn store_test_data(
    consensus: &ConsensusClient,
    signing_key: &SigningKey,
    app_id: &str,
    subgrove_id: &str,
    key: &str,
    data: serde_json::Value,
    did: &str,
    public_key_id: &str,
    nonce: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = StoreDataRequest {
        app_id: app_id.to_string(),
        subgrove_id: subgrove_id.to_string(),
        key: key.to_string(),
        data,
        owner_did: did.to_string(),
        signature: vec![],
        public_key_id: public_key_id.to_string(),
        nonce,
    };
    let tx_hash = consensus.store_data(request, signing_key).await?;
    consensus.wait_for_transaction(&tx_hash, 10).await?;
    Ok(())
}

#[tokio::test]
async fn test_get_with_automatic_proof_verification() {
    let (client, consensus, did_info, signing_key, app_id, subgrove_id) =
        match setup_test_environment().await {
            Ok(setup) => setup,
            Err(e) => {
                eprintln!(
                    "Test setup failed: {}. Make sure Willow and CometBFT are running.",
                    e
                );
                return;
            }
        };

    // Store test data via consensus
    let test_data = json!({
        "id": "test-001",
        "value": 42,
        "description": "Test item for proof verification"
    });

    store_test_data(
        &consensus,
        &signing_key,
        &app_id,
        &subgrove_id,
        "test-key",
        test_data.clone(),
        &did_info.did,
        &did_info.public_key_id,
        4,
    )
    .await
    .expect("Failed to store test data");

    // Test automatic proof verification on GET
    let retrieved_data = client
        .data()
        .get(&app_id, &subgrove_id, "test-key")
        .await
        .expect("Failed to retrieve data with proof verification");

    // Verify the data matches
    assert_eq!(retrieved_data["id"], "test-001");
    assert_eq!(retrieved_data["value"], 42);
}

#[tokio::test]
async fn test_get_unverified_skips_proof_check() {
    let (client, consensus, did_info, signing_key, app_id, subgrove_id) =
        match setup_test_environment().await {
            Ok(setup) => setup,
            Err(e) => {
                eprintln!(
                    "Test setup failed: {}. Make sure Willow and CometBFT are running.",
                    e
                );
                return;
            }
        };

    // Store test data via consensus
    let test_data = json!({
        "id": "test-002",
        "value": 100
    });

    store_test_data(
        &consensus,
        &signing_key,
        &app_id,
        &subgrove_id,
        "test-key-2",
        test_data.clone(),
        &did_info.did,
        &did_info.public_key_id,
        4,
    )
    .await
    .expect("Failed to store test data");

    // Test unverified GET (should not request or verify proof)
    let retrieved_data = client
        .data()
        .get_unverified(&app_id, &subgrove_id, "test-key-2")
        .await
        .expect("Failed to retrieve data without verification");

    // Verify the data matches
    assert_eq!(retrieved_data["id"], "test-002");
    assert_eq!(retrieved_data["value"], 100);
}

#[tokio::test]
async fn test_query_with_automatic_proof_verification() {
    let (client, consensus, did_info, signing_key, app_id, subgrove_id) =
        match setup_test_environment().await {
            Ok(setup) => setup,
            Err(e) => {
                eprintln!(
                    "Test setup failed: {}. Make sure Willow and CometBFT are running.",
                    e
                );
                return;
            }
        };

    // Store multiple test items via consensus
    let items = vec![
        ("item-1", json!({"id": "item-1", "value": 10})),
        ("item-2", json!({"id": "item-2", "value": 20})),
        ("item-3", json!({"id": "item-3", "value": 30})),
    ];

    for (i, (key, data)) in items.into_iter().enumerate() {
        store_test_data(
            &consensus,
            &signing_key,
            &app_id,
            &subgrove_id,
            key,
            data,
            &did_info.did,
            &did_info.public_key_id,
            4 + i as u64,
        )
        .await
        .expect("Failed to store test data");
    }

    // Wait for data to be indexed
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Test automatic proof verification on QUERY
    let query = json!({
        "filters": {
            "value": {"$gte": 15}
        },
        "limit": 10
    });

    let response = client
        .data()
        .query(&app_id, &subgrove_id, query)
        .await
        .expect("Failed to execute query with proof verification");

    // Should have 2 results (value >= 15)
    assert_eq!(response.documents.len(), 2);

    // Verify root hash is present (only when proof was verified)
    assert!(
        response.verified_root_hash.is_some(),
        "Expected verified root hash in response"
    );
}

#[tokio::test]
async fn test_query_unverified_skips_proof_check() {
    let (client, consensus, did_info, signing_key, app_id, subgrove_id) =
        match setup_test_environment().await {
            Ok(setup) => setup,
            Err(e) => {
                eprintln!(
                    "Test setup failed: {}. Make sure Willow and CometBFT are running.",
                    e
                );
                return;
            }
        };

    // Store test data via consensus
    let test_data = json!({
        "id": "test-unverified",
        "value": 999
    });

    store_test_data(
        &consensus,
        &signing_key,
        &app_id,
        &subgrove_id,
        "unverified-key",
        test_data,
        &did_info.did,
        &did_info.public_key_id,
        4,
    )
    .await
    .expect("Failed to store test data");

    // Wait for indexing
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Test unverified QUERY
    let query = json!({
        "filters": {
            "value": {"$eq": 999}
        }
    });

    let response = client
        .data()
        .query_unverified(&app_id, &subgrove_id, query)
        .await
        .expect("Failed to execute unverified query");

    // Should have 1 result
    assert_eq!(response.documents.len(), 1);

    // Verified root hash should NOT be present
    assert!(
        response.verified_root_hash.is_none(),
        "Unexpected verified root hash in unverified query"
    );
}

#[tokio::test]
async fn test_proof_verification_error_handling() {
    let (client, _consensus, _did_info, _signing_key, app_id, subgrove_id) =
        match setup_test_environment().await {
            Ok(setup) => setup,
            Err(e) => {
                eprintln!(
                    "Test setup failed: {}. Make sure Willow and CometBFT are running.",
                    e
                );
                return;
            }
        };

    // Test retrieving non-existent key
    match client
        .data()
        .get(&app_id, &subgrove_id, "non-existent-key")
        .await
    {
        Ok(_) => panic!("Expected error for non-existent key"),
        Err(WillowError::NotFound(_)) => {
            // Expected error
        }
        Err(e) => panic!("Unexpected error type: {}", e),
    }
}

#[tokio::test]
#[ignore] // Requires a running node
async fn test_verified_root_hash_endpoint() {
    let client = match WillowClient::new("http://localhost:3031").await {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "Failed to create client: {}. Make sure Willow is running.",
                e
            );
            return;
        }
    };

    // Test the verified root hash endpoint
    let verified_hash = client
        .get_root_hash()
        .await
        .expect("Failed to get verified root hash");

    // Should have a valid hash
    assert!(!verified_hash.is_empty(), "Expected non-empty root hash");
    assert_eq!(verified_hash.len(), 64, "Expected 64-char hex hash");

    // Test local root hash endpoint
    let local_hash = client
        .get_root_hash_local()
        .await
        .expect("Failed to get local root hash");

    assert!(!local_hash.is_empty(), "Expected non-empty local root hash");

    println!("✅ Verified root hash: {}", &verified_hash[..16]);
    println!("✅ Local root hash: {}", &local_hash[..16]);
}
