# Willow Rust SDK

A Rust SDK for interacting with the Willow decentralized data infrastructure protocol. Provides trustless verification of all data operations through an embedded CometBFT light client and GroveDB proof verification.

## Features

- **Trustless by Default**: Embedded light client verifies all data against blockchain consensus
- **GroveDB Proof Verification**: Merkle proofs verified locally using lightweight verify-only mode
- **DID Authentication**: Ed25519 and secp256k1 signature support
- **Automatic Proof Verification**: All `get()` and `query()` operations verify proofs automatically
- **GraphQL Indexing**: Query indexed blockchain data with cryptographic proofs
- **Token Operations**: Check balances, fees, and token information
- **Async/Await**: Built on Tokio for high performance
- **Zero-Cost Abstractions**: Rust native with minimal overhead

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
willow-sdk = "0.1.0"
tokio = { version = "1", features = ["full"] }
```

To disable proof verification (if you trust your node):

```toml
[dependencies]
willow-sdk = { version = "0.1.0", features = ["no-light-client"] }
```

## Quick Start

```rust
use willow_sdk::{WillowClient, auth::generate_did, types::SignatureAlgorithm};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client
    let client = WillowClient::new("http://localhost:3031").await?;

    // Generate DID
    let did_info = generate_did(SignatureAlgorithm::Ed25519)?;

    // Register and authenticate
    client.register_did(&did_info.did_document).await?;
    client.authenticate(
        &did_info.did,
        &did_info.private_key_hex(),
        &did_info.public_key_id
    ).await?;

    // All data operations automatically verify proofs
    let data = client.data().get("app_id", "dataset_id", "key").await?;

    Ok(())
}
```

## Light Client Configuration

For trustless verification against multiple validators:

```rust
use willow_sdk::{WillowClient, LightClientConfig};
use std::time::Duration;

let light_client_config = LightClientConfig::builder("willow-mainnet")
    .validator_endpoints(vec![
        "http://validator1:26657".to_string(),
        "http://validator2:26657".to_string(),
        "http://validator3:26657".to_string(),
    ])
    .trust_threshold(2, 3)  // 2/3+ validator signatures required
    .trusting_period(Duration::from_secs(86400))  // 24 hours
    .max_clock_drift(Duration::from_secs(10))
    .auto_sync(true)  // Sync to latest on creation
    .build();

let client = WillowClient::builder()
    .api_url("http://localhost:3031")
    .light_client_config(light_client_config)
    .build()
    .await?;

// All operations now verified against validator consensus
let data = client.data().get("app_id", "dataset_id", "key").await?;
```

### Persisting Light Client State

Save and restore verified headers across sessions:

```rust
// Export state before shutdown
let state = client.light_client().unwrap().export_trusted_state().await;
let json = serde_json::to_string(&state)?;
std::fs::write("light_client_state.json", json)?;

// Restore state on startup
let json = std::fs::read_to_string("light_client_state.json")?;
let state: TrustedState = serde_json::from_str(&json)?;
client.light_client().unwrap().import_trusted_state(state).await?;
```

## Data Operations

### Retrieve Data (Verified by Default)

```rust
// Automatically verifies proof against consensus
let data = client.data().get("app_id", "dataset_id", "key").await?;

// Query with automatic proof verification
let response = client.data().query("app_id", "dataset_id", json!({
    "filters": { "status": "active" },
    "limit": 10
})).await?;

// Check the verified root hash
if let Some(root_hash) = response.verified_root_hash {
    println!("Verified against root: {}", root_hash);
}
```

### Skip Verification (For Performance)

```rust
// When you trust the node or need maximum performance
let data = client.data().get_unverified("app_id", "dataset_id", "key").await?;
let response = client.data().query_unverified("app_id", "dataset_id", query).await?;
```

### Store Data

```rust
use serde_json::json;

// Store single item
client.data().store_item(
    "app_id",
    "dataset_id",
    "key",
    json!({ "name": "Alice", "score": 100 })
).await?;

// Batch store
let items = vec![
    ("key1".to_string(), json!({ "name": "Item 1" })),
    ("key2".to_string(), json!({ "name": "Item 2" })),
];
client.data().batch_store("app_id", "dataset_id", items).await?;
```

### Update and Delete

```rust
client.data().update("app_id", "dataset_id", "key", json!({ "updated": true })).await?;
client.data().delete("app_id", "dataset_id", "key").await?;
```

## DID Operations

### Generate DIDs

```rust
use willow_sdk::{auth::generate_did, types::SignatureAlgorithm};

// Ed25519 (faster, recommended)
let ed25519_did = generate_did(SignatureAlgorithm::Ed25519)?;

// Secp256k1 (Ethereum/Bitcoin compatible)
let secp256k1_did = generate_did(SignatureAlgorithm::Secp256k1)?;

println!("DID: {}", ed25519_did.did);
println!("Private Key: {}", ed25519_did.private_key_hex());
```

### Manual Signing

```rust
use willow_sdk::auth::{sign_challenge, verify_signature};

let message = "Hello, Willow!";
let signature = sign_challenge(message, &private_key_hex, SignatureAlgorithm::Ed25519)?;
let is_valid = verify_signature(message, &signature, &public_key_hex, SignatureAlgorithm::Ed25519)?;
```

## GraphQL Indexing

Query indexed blockchain data with cryptographic proofs:

```rust
// Query a subgrove
let result = client.indexing().graphql_query(
    "uniswap-v3",
    r#"
        query {
            swaps(first: 10) {
                id
                amount0
                amount1
                timestamp
            }
        }
    "#,
    None
).await?;

// List available subgroves
let subgroves = client.indexing().list_subgroves().await?;

// Get subgrove status
let status = client.indexing().get_subgrove_status("uniswap-v3").await?;
println!("Synced to block: {}", status.synced_block);

// List indexers
let indexers = client.indexing().list_indexers().await?;
```

## Token Operations

```rust
// Get WILL token info
let info = client.token().get_info().await?;
println!("Symbol: {}, Total Supply: {}", info.symbol, info.total_supply);

// Check DID balance
let balance = client.token().get_balance("did:willow:abc123").await?;
println!("Balance: {} WILL", balance.balance);

// Check app balance
let app_balance = client.token().get_app_balance("my-app").await?;

// Get fee schedule
let fees = client.token().get_fee_schedule().await?;
println!("Storage fee: {} per byte", fees.storage_fee_per_byte);
```

## Registration

### Register App

```rust
use willow_sdk::types::RegisterAppRequest;

let app = client.registration().register_app(RegisterAppRequest {
    app_id: "my-app".to_string(),
    name: "My Application".to_string(),
    description: "Built with Willow".to_string(),
    app_type: "application".to_string(),
    owner_did: session.did.clone(),
    admins: vec![],
    requires_graph_node: false,
}).await?;
```

### Register Dataset

```rust
use willow_sdk::types::{RegisterDatasetRequest, SchemaDefinition, FieldType};
use std::collections::HashMap;

let mut fields = HashMap::new();
fields.insert("id".to_string(), FieldType::String);
fields.insert("name".to_string(), FieldType::String);
fields.insert("balance".to_string(), FieldType::Number);

let dataset = client.registration().register_dataset(RegisterDatasetRequest {
    dataset_id: "users".to_string(),
    app_id: "my-app".to_string(),
    name: "Users".to_string(),
    dataset_path: vec!["data".to_string()],
    schema: SchemaDefinition {
        version: 1,
        fields,
        indexes: vec!["name".to_string()],
        required_fields: vec!["id".to_string()],
    },
    owner_did: session.did.clone(),
    writers: vec![session.did.clone()],
    readers: vec![],
}).await?;
```

## Root Hash Verification

```rust
// Get consensus-verified root hash (recommended for security)
let verified_root = client.get_root_hash().await?;

// Get local node's root hash (for debugging)
let local_root = client.get_root_hash_local().await?;

// Compare to ensure node is in sync
if verified_root != local_root {
    println!("Warning: Node may be out of sync");
}
```

## Error Handling

```rust
use willow_sdk::{WillowError, Result};

match client.data().get("app", "dataset", "key").await {
    Ok(data) => println!("Data: {}", data),
    Err(WillowError::NotFound(msg)) => println!("Not found: {}", msg),
    Err(WillowError::ProofVerificationFailed(msg)) => {
        // Data tampering or stale state detected
        eprintln!("Proof verification failed: {}", msg);
    }
    Err(WillowError::NotAuthenticated) => println!("Please authenticate"),
    Err(WillowError::SessionExpired) => println!("Session expired"),
    Err(WillowError::LightClient(msg)) => println!("Light client error: {}", msg),
    Err(e) => println!("Error: {}", e),
}
```

## Client Configuration

```rust
use willow_sdk::{WillowClient, utils::RetryConfig};
use std::time::Duration;

let client = WillowClient::builder()
    .api_url("https://api.willow.network")
    .timeout(Duration::from_secs(60))
    .retry_config(RetryConfig {
        max_attempts: 5,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(10),
        exponential_base: 2.0,
    })
    .build()
    .await?;
```

## Validators

```rust
// List validators
let validators = client.validators().list().await?;

// Get validator info
let validator = client.validators().get("validator_address").await?;
```

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_generate_did
```

## Security Model

The SDK provides three levels of security:

1. **Full Trustless** (with light client configured)
   - Verifies 2/3+ validator signatures on block headers
   - Extracts trusted `app_hash` from consensus
   - Verifies GroveDB proofs against `app_hash`
   - No trust in any single node required

2. **Root Hash Verification** (default)
   - Verifies GroveDB proofs locally
   - Compares against `/state/root-hash/verified` endpoint
   - Trusts that the API returns correct consensus state

3. **Unverified** (opt-in via `_unverified` methods)
   - Trusts the node completely
   - Maximum performance
   - Use only with trusted nodes

## License

MIT
