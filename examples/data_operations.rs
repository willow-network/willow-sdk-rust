//! Data operations example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Storing single items
//! - Batch storing multiple items
//! - Updating data
//! - Deleting data
//! - Querying with filters
//! - Verified vs unverified operations
//!
//! Run with: cargo run --example data_operations

use serde_json::json;
use willow_sdk::{WillowClient, DEVNET_VALIDATOR_1};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Willow SDK - Data Operations Example");
    println!("=====================================\n");

    // Setup: Create client and authenticate with devnet test account
    let client = WillowClient::new("http://localhost:3031").await?;
    client.set_identity(
        DEVNET_VALIDATOR_1.did,
        DEVNET_VALIDATOR_1.private_key,
        DEVNET_VALIDATOR_1.public_key_id,
    );

    println!("Authenticated as: {}\n", DEVNET_VALIDATOR_1.did);

    let app_id = "example-app";
    let dataset_id = "products";

    // 1. Store single item
    println!("1. Storing single item...");
    let product1 = json!({
        "name": "Widget",
        "price": 29.99,
        "category": "electronics",
        "in_stock": true
    });

    match client
        .data()
        .store_item(app_id, dataset_id, "product-1", product1)
        .await
    {
        Ok(_) => println!("   Stored product-1"),
        Err(e) => println!("   Note: {}", e),
    }

    // 2. Batch store multiple items
    println!("\n2. Batch storing items...");
    let items = vec![
        (
            "product-2".to_string(),
            json!({
                "name": "Gadget",
                "price": 49.99,
                "category": "electronics",
                "in_stock": true
            }),
        ),
        (
            "product-3".to_string(),
            json!({
                "name": "Gizmo",
                "price": 19.99,
                "category": "toys",
                "in_stock": false
            }),
        ),
        (
            "product-4".to_string(),
            json!({
                "name": "Thingamajig",
                "price": 99.99,
                "category": "electronics",
                "in_stock": true
            }),
        ),
    ];

    match client.data().batch_store(app_id, dataset_id, items).await {
        Ok(_) => println!("   Stored 3 products in batch"),
        Err(e) => println!("   Note: {}", e),
    }

    // 3. Get with proof verification (secure by default)
    println!("\n3. Get with proof verification...");
    match client.data().get(app_id, dataset_id, "product-1").await {
        Ok(data) => {
            println!("   Retrieved and VERIFIED:");
            println!("   {}", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 4. Get without verification (faster)
    println!("\n4. Get without verification (unverified)...");
    match client
        .data()
        .get_unverified(app_id, dataset_id, "product-2")
        .await
    {
        Ok(data) => {
            println!("   Retrieved (unverified):");
            println!("   {}", serde_json::to_string_pretty(&data)?);
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 5. Update data
    println!("\n5. Updating data...");
    let updated_product = json!({
        "name": "Widget Pro",
        "price": 39.99,
        "category": "electronics",
        "in_stock": true,
        "updated": true
    });

    match client
        .data()
        .update(app_id, dataset_id, "product-1", updated_product)
        .await
    {
        Ok(_) => println!("   Updated product-1"),
        Err(e) => println!("   Note: {}", e),
    }

    // 6. Query with filters (verified)
    println!("\n6. Query with filters (verified)...");
    let query = json!({
        "filters": {
            "category": "electronics",
            "in_stock": true
        },
        "limit": 10
    });

    match client.data().query(app_id, dataset_id, query).await {
        Ok(response) => {
            println!("   Found {} documents", response.documents.len());
            if let Some(root_hash) = response.verified_root_hash {
                println!(
                    "   Verified against root: {}...",
                    &root_hash[..16.min(root_hash.len())]
                );
            }
            for doc in &response.documents {
                println!("   - {}", serde_json::to_string(doc)?);
            }
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 7. Query without verification (faster)
    println!("\n7. Query without verification...");
    let query = json!({
        "limit": 5
    });

    match client
        .data()
        .query_unverified(app_id, dataset_id, query)
        .await
    {
        Ok(response) => {
            println!(
                "   Found {} documents (unverified)",
                response.documents.len()
            );
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 8. Delete data
    println!("\n8. Deleting data...");
    match client.data().delete(app_id, dataset_id, "product-3").await {
        Ok(_) => println!("   Deleted product-3"),
        Err(e) => println!("   Note: {}", e),
    }

    // 9. Compare root hashes
    println!("\n9. Comparing root hashes...");
    let verified_root = client.get_root_hash().await.ok();
    let local_root = client.get_root_hash_local().await.ok();

    match (verified_root, local_root) {
        (Some(v), Some(l)) => {
            println!("   Verified root: {}...", &v[..16.min(v.len())]);
            println!("   Local root:    {}...", &l[..16.min(l.len())]);
            if v == l {
                println!("   Node is in sync with consensus");
            } else {
                println!("   Node has pending changes");
            }
        }
        _ => println!("   Could not retrieve root hashes"),
    }

    println!("\nData operations example complete!");
    Ok(())
}
