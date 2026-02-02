# Willow SDK Operation Examples

Single-purpose examples for testing. Each does one thing - modify the configuration section and run.

## Prerequisites

```bash
./scripts/start_network.sh
```

## Write Operations

```bash
cargo run --example register_did       # Register a new DID
cargo run --example register_app       # Register an application
cargo run --example register_subgrove  # Create a subgrove
cargo run --example store_data         # Store data
cargo run --example transfer           # Transfer tokens
cargo run --example fund_app           # Fund an app
```

## Read Operations

```bash
cargo run --example query_data         # Query stored data
cargo run --example check_balances     # Check token balances
cargo run --example list_registrations # List apps and subgroves
```

## Configuration

Each example has a `CONFIGURATION` section at the top. Modify these values for your testing:

```rust
// =========================================================================
// CONFIGURATION - Modify these values for your testing
// =========================================================================
let app_id = "my-app";
let subgrove_id = "users";
let nonce: u64 = 0;
// =========================================================================
```

## Nonce Management

Each DID has a nonce that must increment with each transaction:
- First transaction: `nonce = 0`
- Second transaction: `nonce = 1`
- etc.

Track your nonces when running multiple examples with the same DID.
