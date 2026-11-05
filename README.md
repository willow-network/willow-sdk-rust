# Willow Rust SDK

A Rust SDK for interacting with the Willow decentralized data infrastructure protocol. A value read by key is verified with a GroveDB proof against the app hash of a CometBFT header; see [What is verified](#what-is-verified) for each read.

## Features

- **Verified Reads by Key**: `data().get` returns a value only when its proof binds it at its key under the chain's app hash
- **GroveDB Proof Verification**: Merkle proofs verified locally using lightweight verify-only mode
- **DID Authentication**: Ed25519 and secp256k1 signature support
- **Nonces per Identity**: concurrent writes take distinct nonces from the node's window
- **File Storage**: Upload, download, list, and delete files with chunk Merkle verification
- **File Encryption**: XChaCha20-Poly1305 encryption/decryption for private files
- **GraphQL Indexing**: Query indexed blockchain data
- **Token Operations**: Check balances, fees, and token information
- **Async/Await**: Built on Tokio for high performance
- **Zero-Cost Abstractions**: Rust native with minimal overhead

> **Install from source.** Willow's SDKs are not yet published to package registries.
> The commands below install directly from this repository and work today.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
willow-sdk = { git = "https://github.com/willow-network/willow-sdk-rust" }
tokio = { version = "1", features = ["full"] }
```

To build without proof verification (reads by key then refuse; use the `_unverified` reads):

```toml
[dependencies]
willow-sdk = { git = "https://github.com/willow-network/willow-sdk-rust", features = ["no-light-client"] }
```

### Building from source

This repo uses path dependencies on two companion crates checked out as siblings
(the same layout CI uses — see `.github/workflows/ci.yml`). Clone them next to
this repo before building:

```bash
git clone https://github.com/willow-network/willow-types.git      ../willow-types-extract
git clone https://github.com/willow-network/willow-gkr-verify.git ../willow-gkr-verify-extract
cargo build
```

## Transaction submission

Transactions submitted through this SDK are bincode-encoded by the client (the chain's on-the-wire format) and broadcast to CometBFT's `broadcast_tx_sync` at the consensus URL (`consensus_url` on the builder, or `ConsensusClient::new`). The client signs the exact transaction it encodes. A client built without a consensus URL can read but not write: the file and key-grant operations return a configuration error naming `consensus_url`. Byte fields of a transaction built as JSON (`signature`, `content`, `encrypted_key`, …) are arrays of numbers 0–255.

### Nonces

The node accepts a nonce in `base + 1 ..= base + 24` that it hasn't used, and `base` advances only over used nonces with no gap. Every write path of `ConsensusClient` (and so the data, file, and key-grant operations) takes its nonce from the client's `NonceTracker`, shared by every clone of the client:

- it reads the account's nonce state over the CometBFT RPC (ABCI `/store/account_nonce_state/{did}`: the base as a big-endian u64, then 3 bytes in which bit `i % 8` of byte `i / 8` marks `base + 1 + i` used), falling back to the base alone from the API's `GET /account/{did}/nonce`;
- it hands out the lowest nonce in the window that the chain doesn't show used and that no write from this client took within the last 120 s (the node holds a pending transaction's nonce for 3 blocks or 120 s), under a lock, so concurrent writes take distinct nonces. When all 24 are taken it fails with `WillowError::NonceWindowFull`, never a nonce past the window;
- a submission CheckTx refuses gives its nonce back, unless the node's refusal of that nonce says it is held by a pending transaction (`Nonce N of … is held by a pending transaction`), used (`Invalid nonce: N already used`, `Invalid nonce: N <= base nonce`), or spent (`… (nonce N spent)`). A submission whose fate is unknown (a network or RPC error) keeps its nonce for 120 s, and CometBFT already holding the exact bytes (`tx already exists in cache`) counts as accepted.

**Retry a write under its own nonce.** A write that was sent and whose outcome is unknown (the node's answer was lost or unreadable, or its RPC answered an error) may yet land. It fails with `WillowError::SubmissionUnknown`, which carries a `SignedSubmission`: the DID, the nonce its signature covers, the exact bytes broadcast, and their hash. To retry it, send those bytes again with `ConsensusClient::rebroadcast(&submission)`: whichever attempt lands first spends the nonce and the other is refused, so the write runs at most once, and CometBFT answers bytes its mempool already holds as `tx already exists in cache`, which counts as accepted. Calling `transfer`, `fund_subgrove`, `store_data`, or any other write again instead signs it under a new nonce, and then both can land.

```rust
match consensus.transfer(from, to, amount, None, key_hex, key_id, algorithm).await {
    Err(WillowError::SubmissionUnknown { submission, .. }) => {
        let tx_hash = consensus.rebroadcast(&submission).await?;
    }
    other => { other?; }
}
```

A write refused as "already used" may be one whose earlier attempt landed: read what it wrote before signing it again under a fresh nonce, or it can run twice. A write refused in its block after its signature and nonce verify has spent its nonce; sign any retry under a fresh one. The key-grant operations and `update_did_with_nonce` take the nonce you pass, and hold and settle it the same way; one the SDK refuses before sending it (a grantee that isn't a DID, …) gives the nonce back. `ConsensusClient::with_nonce_tracker` shares one tracker between clients that sign for the same identity.

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

    // Verified: the proof binds the value at its key under the chain's app hash
    let data = client.data().get("dataset_id", "key").await?;

    Ok(())
}
```

## What is verified

A read is presented as verified only when a proof binds that exact data at the GroveDB path and key asked, against a root that doesn't come from the response itself.

- **`data().get(subgrove, key)`** reads the value and its proof, and returns the value only when the proof proves an Item at `key` in the subgrove's data tree (`[subgroves, subgrove, data]`) whose bytes are the value served, and the root it computes is the `app_hash` of the CometBFT header at the proof's height + 1 (the state after block `H` is committed in block `H + 1`'s header). The header comes from the light client's validator endpoints, over the CometBFT RPC: those of `light_client_config` when set, else the consensus URL. Only an API on a loopback host (`localhost`, `127.0.0.1`, `::1`) at port 3031, as a local node runs, implies its node at port 26657 without one; any other API URL with no consensus URL is a configuration error (`WillowError::Config`). A missing proof or height, another value, another root, or no header is an error; nothing is returned unverified. A key the API reports missing is `NotFound`, unproven.
- **Recency**: the API chooses the height it proves at, so `data().get` refuses a state more than `max_proof_lag_blocks` (default 20, on `LightClientConfig`) behind the chain's latest height (the endpoints' CometBFT `/status`), unless a header within that lag still carries the same root (a block without transactions leaves the app hash unchanged, so an idle chain's old state is still its state); it refuses a height that far ahead too. Both are `WillowError::ProofHeightOutOfRange`, distinct from a forged proof's `ProofVerificationFailed`. `data().get_verified` returns the value with the height of the header found to carry its root (`VerifiedValue { value, height }`): the value is the chain's state as of that header, not necessarily as of now. The light client's `verify_item` checks a proof at the height you pass, however old; `LightClient::verify_root_after` applies the recency rule.
- **Proof checks** refuse what grovedb 3.1.0's verifier alone accepts: a proof that doesn't descend the asked path, children attached under an opaque `Hash` node (a forged subtree that still hashes to the real root), an item whose value its root doesn't bind (a `KVValueHash` node carries only the value's hash into the root), and a lone root hash (`Push(Hash(root))`). They also refuse an element of exactly 63 bytes (an Item with a 60-byte value and no flags) outside a subgrove's data tree, since a proof can't tell its `KV` node from a subtree's or a reference's; a subgrove's data tree (`[subgroves, <id>, data]`), which holds only Items, accepts it. Before grovedb (whose 3.1.0 decoder trusts the lengths it reads) sees a proof, the SDK bounds-checks its encoding without recursion (every length within the bytes left, at most 64 levels of nesting and 1024 layers, at most 32 MiB) and decodes every node value as an element within its 64 KiB bound, so a hostile proof is refused rather than crashing the process. `ProofVerifier::verify_item_at_path` and `verify_item_against_root`, and the light client's `verify_item`, check a proof for an Item at a path and key with a given value. The path-less `verify_query_proof`, `verify_item_proof`, `verify_against_root`, and the light client's `verify_proof` are deprecated and refuse.
- **Trust model**: verified reads check the proof against the app hash that a consensus node the caller configures reports, and the SDK trusts that node: it does not verify validator signatures over CometBFT's canonical vote bytes. The light client takes headers as its endpoints serve them, trusting the first, so it does not check 2/3+ of the validators' signatures. Configure endpoints you trust.
- **Unverified**: `data().query` and `query_historical_verified` refuse (`WillowError::Unsupported`), since the API serves a query's documents without their keys and a historical answer without the indexer's proof, and the checkpoint root comes from the same API. `query_unverified`, `query_historical`, `sql`, and GraphQL return their answers unverified, as do `get_root_hash` and `get_root_hash_local` (the API's word).
- **Verifiable RPC** (`verifiable_rpc().query`) binds the indexer's answer to its GroveDB proof at the key in one entity tree, and in strict mode checks the GKR proofs, but against the `state_root` the indexer names in the same response: the answer is unverified against the chain (`state_root_anchored` is `false`). An absent answer is refused in the checking modes.
- **Ethereum state reads** (`eth()`) require the proof to be of the account, slots, and block asked, and walk it against the `state_root` in the same response. The SDK has no Ethereum light client, so check `state_root` against a header you trust; `eth_call`'s return data is not proven.
- **Block completeness** (`verify_block_completeness`) checks the indexer's served logs against the `events_commitment` the consensus RPC answers without a proof: it trusts that RPC node, not the indexer.
- **File downloads** check each chunk against the manifest's chunk Merkle root and content hash; the manifest itself is the API's, unproven.

## Light Client Configuration

The validator endpoints verified reads take headers from:

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
    .max_proof_lag_blocks(20)  // Refuse a verified read's state older than this
    .auto_sync(true)  // Sync to latest on creation
    .build();

let client = WillowClient::builder()
    .api_url("http://localhost:3031")
    .light_client_config(light_client_config)
    .build()
    .await?;

// Verified against the header after the proof's block, from these endpoints
let data = client.data().get("dataset_id", "key").await?;
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

### Retrieve Data

```rust
// Verified: the value its proof binds at the key, under the chain's app hash
let data = client.data().get("dataset_id", "key").await?;

// A query's documents are returned unverified
let response = client.data().query_unverified("dataset_id", json!({
    "filters": { "status": "active" },
    "limit": 10
})).await?;
```

### Unverified Reads

```rust
// When you trust the node
let data = client.data().get_unverified("dataset_id", "key").await?;
```

### Store, Update, and Delete Data

All data writes go through consensus transactions to ensure all nodes maintain consistent state:

```rust
use willow_sdk::types::StoreDataRequest;

let request = StoreDataRequest {
    subgrove_id: "dataset_id".to_string(),
    key: "key".to_string(),
    data: json!({ "name": "Alice", "score": 100 }),
    owner_did: did_info.did.clone(),
    signature: vec![],
    public_key_id: did_info.public_key_id.clone(),
    nonce: 0, // ignored: the client takes the nonce
};
let tx_hash = consensus_client.store_data(request, &signing_key).await?;
```

`data` is sent as its JSON text. The client takes the nonce ([Nonces](#nonces)), then signs labelled lines that bind it and every field the transaction writes, joined by `\n` (the byte 0x0A) with no trailing newline. Text fields go in verbatim as UTF-8:

```text
StoreData
Subgrove: <subgrove_id>
Key: <key>
Owner: <owner_did>
DataHash: <lowercase hex SHA-256 of the data bytes the transaction carries>
Nonce: <nonce>
```

`UpdateData` signs the same lines under its own name. `DeleteData` and a file delete's `DeleteFileManifest` sign `Subgrove`, `Key`, `Owner`, and `Nonce`. A file upload's `StoreFileManifest` signs every manifest field: `Subgrove`, `Key`, `Owner`, `Filename`, `ContentType`, `TotalSize`, `ContentHash`, `ChunkCount`, `ChunkSize`, `ChunkMerkleRoot`, `Encryption` (`none`, or `<key epoch>:<hex nonce>`), and `Nonce`. A subgrove ID, key, owner DID, filename, or content type holding the byte 0x0A is refused. A write the node refuses in its block after its signature and nonce verify still spends its nonce; calling again takes the next free nonce and signs anew. Writes in flight together may land in any order, so send a write that depends on another (an update of a key being stored) only after the first has landed. A file upload sends its chunks only once its manifest has landed and executed. `files().upload` and `files().delete` need a signing key and its key ID (the node refuses an unsigned file transaction): without them they fail with `WillowError::Validation` before anything is sent. `store_data` refuses `data` that isn't a JSON object, as the node does, before taking a nonce. The `signed_messages` module builds each message from the transaction it signs (`store_data`, `update_data`, `delete_data`, `store_file_manifest`, `delete_file_manifest`).

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

### Request Signing

With an identity set, the client signs each read of subgrove data it sends to the API (`GET /data/{sg}/{key}`, `GET /proof/{sg}/{key}`, and `POST /query`, `/sql`, `/graphql`, and `/a2a`) with a one-time nonce over the whole request. Only this form carries the DID's read rights: a Reader permission on a subgrove, or a place on a priced subgrove's free-reader list. Other requests it signs use the older form below, which the server also accepts in the first 30 s after it restarts, when it refuses nonce-signed requests.

The headers are `X-DID`, `X-Public-Key-ID`, `X-Signature`, `X-Timestamp`, and `X-Nonce`. The signature is over eight lines:

```text
willow-request-v2
<DID>
<public key id>
<METHOD>
<path and query, exactly as sent>
<Unix timestamp>
<nonce>
<hex SHA-256 of the body>
```

- The server accepts a timestamp up to 300 s old and 30 s ahead of its clock, and each (DID, nonce) once. The client signs each retry with a new nonce.
- A nonce is 16 to 128 characters of `A-Z a-z 0-9 - _`. `auth::new_request_nonce` makes one of 32 hex characters.
- Ed25519 signatures are sent as hex. secp256k1 signatures are over the Keccak-256 of the message and are sent as `0x`-prefixed hex. A generated secp256k1 DID document, and `DidInfo::public_key`, carry the 33-byte compressed key.
- Requests sent to an indexer (`indexer_url`) are not signed this way.

To sign a request you send yourself:

```rust
use willow_sdk::auth::sign_request_with_nonce;

let headers = sign_request_with_nonce(
    &did, &public_key_id, &private_key_hex, SignatureAlgorithm::Ed25519,
    "POST", "/query/my-subgrove", body_bytes,
)?;
```

`auth::legacy_request_message(method, path, timestamp)` is the older `{METHOD}:{PATH}:{TIMESTAMP}` form, over the path without its query string. It proves the DID but carries none of its read rights, and it can be replayed with any body until the timestamp expires.

### Rotate a DID's signing key

`examples/rotate_did.rs` swaps a DID's on-chain key for a fresh one, signing the
`UpdateDid` transaction with the key being retired. It derives the replacement
document from the live on-chain document, writes the new private key out mode
0600 before any network call, and refuses to broadcast unless a probe signed
with that key verifies against the replacement's authentication set — a
replacement naming a key nobody holds would brick the DID permanently.

It is a dry run unless `--broadcast` is passed:

```bash
# Rehearse: writes the new key, prints the replacement document, the exact
# bytes the chain will verify, and the nonce. Submits nothing.
cargo run --release --example rotate_did -- \
  --did did:willow:validator1 \
  --current-key-file ~/.willow/keys/validator1.key \
  --current-key-id did:willow:validator1#key-1 \
  --new-key-out ~/.willow/keys/validator1.new.key

# Submit, using the key the rehearsal wrote.
cargo run --release --example rotate_did -- \
  --did did:willow:validator1 \
  --current-key-file ~/.willow/keys/validator1.key \
  --current-key-id did:willow:validator1#key-1 \
  --new-key-in ~/.willow/keys/validator1.new.key \
  --broadcast
```

The building blocks are in [`willow_sdk::did_rotation`](src/did_rotation.rs) if
you need them outside the example.

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
println!("Symbol: {}, Max Supply: {}", info.symbol, info.max_supply);

// Check DID balance
let balance = client.token().get_balance("did:willow:abc123").await?;
println!("Balance: {} WILL", balance.balance);

// Check subgrove balance
let subgrove_balance = client.token().get_subgrove_balance("my-subgrove").await?;

// Get fee schedule
let fees = client.token().get_fee_schedule().await?;
println!("Base TX cost: {} wei", fees.base_tx_cost);
println!("Cost per byte: {} wei", fees.cost_per_byte);
```

## Registration

### Register Subgrove

Subgroves are registered via consensus transactions:

```rust
use willow_sdk::types::{RegisterSubgroveRequest, SchemaDefinition, FieldType};
use std::collections::HashMap;

let mut fields = HashMap::new();
fields.insert("id".to_string(), FieldType::String);
fields.insert("name".to_string(), FieldType::String);
fields.insert("balance".to_string(), FieldType::Number);

let request = RegisterSubgroveRequest {
    subgrove_id: "users".to_string(),
    name: "Users".to_string(),
    description: "User data collection".to_string(),
    schema: Some(SchemaDefinition {
        version: 1,
        fields,
        indexes: vec![],
        required_fields: vec!["id".to_string()],
    }),
    owner_did: did_info.did.clone(),
    admins: vec![],
    initial_funding: None,
    writers: vec![did_info.did.clone()],
    readers: vec![],
    signature: vec![],
    public_key_id: did_info.public_key_id.clone(),
    nonce: 0, // ignored: the client takes the nonce
};
let tx_hash = consensus_client.register_subgrove(request, &signing_key).await?;
```

`register_subgrove`, `register_file_subgrove`, and `register_blockchain_subgrove` (from a `SubgroveDefinition`) build the whole `RegisterSubgroveTx`, every field set explicitly, take the nonce, and sign five lines:

```text
RegisterSubgrove
Subgrove: <subgrove_id>
Owner: <owner_did>
Config: <hex SHA-256 of the RegisterSubgroveTx's bincode with an empty signature>
Nonce: <nonce>
```

`Config` hashes the transaction struct (not the `Transaction` enum) with bincode 1.x's default encoding, so it binds every field of every mode: name, description, schema, admins, initial funding, TEE requirement, mode settings, privacy, owner key grant, template, confirmation depth, key ID, nonce, and cryptographic completeness. The client broadcasts exactly the transaction it hashed. `signed_messages::register_subgrove` builds the message for any `RegisterSubgroveTx`, and `signed_messages::register_subgrove_config` gives the hash; both are the node's own forms from `willow_types::consensus::signed_messages`.

A registration the node refuses whatever its signature is refused before signing (`signed_messages::check_register_subgrove`): a DataStorage or FileStorage registration whose subgrove ID isn't 1 to 64 ASCII letters, digits, `-`, or `_` starting with a letter or digit, whose admins, writers, or free readers aren't DIDs (`did:willow:` then letters, digits, `-`, or `_`, at most 128 bytes), or whose `schema` doesn't parse as the node's `SchemaDefinition` (`{"version": 1, "fields": {"<name>": "string" | "number" | "boolean" | "array" | "object" | "bytes"}, "indexes": [], "required_fields": [...]}`, each key optional) or declares indexes; and a private DataStorage registration whose `initial_owner_key_grant` isn't key epoch 0 to the owner. A subgrove definition's `execution_mode` must be `ConsensusExecution`, `IndexerExecution`, or `TeeExecution`, and its `required_tee` `AwsNitro`, `IntelSgx`, or `AmdSev`; any other value is refused before signing.

### Private subgroves: key grants

`client.privacy()` grants, rotates, and revokes a private subgrove's key with the nonce you pass (take one with `ConsensusClient::get_next_nonce`). A grant signs every field of the `EncryptedKeyGrant`:

```text
GrantSubgroveKey
Subgrove: <subgrove_id>
Sender: <sender_did>
Grantee: <grantee_did>
GranteeKey: <grantee_public_key_id>
KeyEpoch: <key_epoch>
EphemeralKey: <hex of ephemeral_public_key>
EncryptedKey: <hex of encrypted_key>
GrantedBy: <granted_by>
GrantedAt: <granted_at>
Nonce: <nonce>
```

A grant's or rotation's grantee must be a DID (`did:willow:` then letters, digits, `-`, or `_`), so a revoke can remove it. A rotation signs `RotateSubgroveKey`, `Subgrove`, `Sender`, `NewEpoch`, `Grants` (the count), then each grant's seven lines from `Grantee` to `GrantedAt` in order, then `Nonce`; a rotation with no grants, or a grant at another key epoch than `NewEpoch`, is refused. A revoke signs `RevokeSubgroveKey:{subgrove_id}:{revokee_did}:{sender_did}:{nonce}`; a subgrove ID holding `:`, or a revokee or sender that isn't a `did:willow:` DID of letters, digits, `-`, and `_`, is refused. `files().unregister_storage_node` signs `UnregisterStorageNode`, `Node`, and `Nonce`. The `signed_messages` module builds each (`grant_subgrove_key`, `rotate_subgrove_key`, `revoke_subgrove_key`, `unregister_storage_node`). A subgrove ID, owner, sender, or node DID, or a grant's grantee, key ID, or granter, holding the byte 0x0A is refused, and each of these transactions spends its nonce when the node refuses it in its block, as the data writes do.

## Root Hashes

Both are the API's word, unverified; verified reads check proofs against a CometBFT header instead.

```rust
// The root the API reports as committed
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

match client.data().get("subgrove", "dataset", "key").await {
    Ok(data) => println!("Data: {}", data),
    Err(WillowError::NotFound(msg)) => println!("Not found: {}", msg),
    Err(WillowError::ProofVerificationFailed(msg)) => {
        // The proof doesn't bind the value served, or its root isn't the chain's
        eprintln!("Proof verification failed: {}", msg);
    }
    Err(WillowError::ProofHeightOutOfRange(msg)) => {
        // A genuine proof of a state the chain has since changed: read again
        println!("Stale answer: {}", msg);
    }
    Err(WillowError::Unsupported(msg)) => println!("Can't verify this read: {}", msg),
    Err(WillowError::NonceWindowFull(msg)) => println!("Wait for writes to land: {}", msg),
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
    .api_url("https://api.willow.tech")
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

Every request the SDK sends times out: after the builder's `timeout` (default 30 s, `client::DEFAULT_TIMEOUT`) for the API, the consensus RPC, and storage nodes, and after the light client's `rpc_timeout` for its validator endpoints. A `ConsensusClient` made with `ConsensusClient::new` uses the default; `with_http_client` gives it your own `reqwest::Client`.

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

See [What is verified](#what-is-verified). In short:

1. **Verified** — `data().get`, and the proof checks that take a path and key: the proof binds the value at its key, and its root is the `app_hash` of a CometBFT header from the light client's endpoints (taken as those endpoints serve it).
2. **Checked against the response's own root** — verifiable RPC (`VerifyMode::Strict` also verifies the GKR proofs) and Ethereum state reads: consistent with the root the indexer names, unverified against the chain.
3. **Unverified** — queries, historical answers, GraphQL and SQL, root hashes, the `_unverified` reads, and `VerifyMode::Disabled`: the node's word.

## License

MIT
