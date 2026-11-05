# Willow SDK Operation Examples

Single-purpose examples for testing. Each does one thing - modify the configuration section and run.

## Prerequisites

```bash
./scripts/start_network.sh
```

## Write Operations

```bash
cargo run --example register_did       # Register a new DID
cargo run --example register_subgrove  # Create a subgrove
cargo run --example store_data         # Store data
cargo run --example transfer           # Transfer tokens
cargo run --example fund_subgrove      # Fund a subgrove
```

## Read Operations

```bash
cargo run --example query_data         # Query stored data
cargo run --example check_balances     # Check token balances
cargo run --example list_registrations # List subgroves
```

## Configuration

Each example has a `CONFIGURATION` section at the top. Modify these values for your testing:

```rust
// =========================================================================
// CONFIGURATION - Modify these values for your testing
// =========================================================================
let subgrove_id = "users";
// =========================================================================
```

## Nonces

The client takes each write's nonce itself: the lowest one the node accepts that the chain doesn't show used and no write from this client holds (see [Nonces](../../README.md#nonces)). A request's `nonce` field is ignored, so there is nothing to track between runs.
