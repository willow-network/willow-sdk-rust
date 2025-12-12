//! Test for the root hash methods

use willow_sdk::WillowClient;

#[tokio::test]
async fn test_root_hash_methods_compile() {
    // This test just ensures the methods exist and have the right signatures
    // It won't actually connect to a server

    let client = WillowClient::new("http://localhost:3031").await.unwrap();

    // These calls will fail without a running server, but they compile correctly
    let _ = client.get_root_hash().await;
    let _ = client.get_root_hash_local().await;

    // Test passes if it compiles
    assert!(true);
}

#[tokio::test]
#[ignore] // Run with: cargo test test_root_hash_methods_with_server -- --ignored --nocapture
async fn test_root_hash_methods_with_server() {
    println!("Testing root hash methods with a running server...");

    let client = WillowClient::new("http://localhost:3031").await.unwrap();

    // Test verified root hash
    match client.get_root_hash().await {
        Ok(verified_hash) => {
            println!("✅ Verified root hash: {}", verified_hash);
            assert!(!verified_hash.is_empty());
            assert!(verified_hash.len() == 64); // Should be 32 bytes hex encoded
        }
        Err(e) => {
            println!("❌ Failed to get verified root hash: {}", e);
            panic!("Could not get verified root hash");
        }
    }

    // Test local root hash
    match client.get_root_hash_local().await {
        Ok(local_hash) => {
            println!("✅ Local root hash: {}", local_hash);
            assert!(!local_hash.is_empty());
            assert!(local_hash.len() == 64); // Should be 32 bytes hex encoded
        }
        Err(e) => {
            println!("❌ Failed to get local root hash: {}", e);
            panic!("Could not get local root hash");
        }
    }

    println!("✅ Both root hash methods work correctly!");
}
