//! GraphQL indexing example for the Willow Rust SDK
//!
//! This example demonstrates:
//! - Listing available subgraphs
//! - Querying indexed blockchain data with GraphQL
//! - Checking subgraph indexing status
//! - Listing indexers
//!
//! Run with: cargo run --example graphql_indexing

use willow_sdk::WillowClient;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Willow SDK - GraphQL Indexing Example");
    println!("======================================\n");

    let client = WillowClient::new("http://localhost:3031").await?;

    // 1. List available subgraphs
    println!("1. Listing available subgraphs...");
    match client.indexing().list_subgraphs().await {
        Ok(subgraphs) => {
            if subgraphs.is_empty() {
                println!("   No subgraphs deployed yet\n");
            } else {
                println!("   Found {} subgraphs:", subgraphs.len());
                for sg in &subgraphs {
                    println!("   - {} ({})", sg.name, sg.subgraph_id);
                    println!("     Status: {:?}", sg.status);
                    println!("     Latest block: {}", sg.latest_block);
                }
                println!();
            }
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 2. Query a subgraph (example: Uniswap V3)
    println!("2. Querying subgraph (example: uniswap-v3)...");
    let query = r#"
        query {
            swaps(first: 5, orderBy: timestamp, orderDirection: desc) {
                id
                amount0
                amount1
                timestamp
                pool {
                    token0 {
                        symbol
                    }
                    token1 {
                        symbol
                    }
                }
            }
        }
    "#;

    match client.indexing().graphql_query("uniswap-v3", query, None).await {
        Ok(response) => {
            println!("   Query result:");
            if let Some(data) = response.data {
                println!("   {}", serde_json::to_string_pretty(&data)?);
            }
            if response.proof.is_some() {
                println!("   Proof included in response");
            }
            if let Some(errors) = response.errors {
                for err in errors {
                    println!("   Error: {}", err.message);
                }
            }
        }
        Err(e) => println!("   Note: {} (subgraph may not exist)\n", e),
    }

    // 3. Query with variables
    println!("\n3. Query with variables...");
    let query_with_vars = r#"
        query GetPool($poolId: ID!) {
            pool(id: $poolId) {
                id
                token0 {
                    symbol
                    name
                }
                token1 {
                    symbol
                    name
                }
                liquidity
                volumeUSD
            }
        }
    "#;

    let variables = json!({
        "poolId": "0x8ad599c3a0ff1de082011efddc58f1908eb6e6d8"
    });

    match client
        .indexing()
        .graphql_query("uniswap-v3", query_with_vars, Some(variables))
        .await
    {
        Ok(response) => {
            println!("   Query result:");
            if let Some(data) = response.data {
                println!("   {}", serde_json::to_string_pretty(&data)?);
            }
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 4. Get subgraph status
    println!("\n4. Getting subgraph indexing status...");
    match client.indexing().get_subgraph_status("uniswap-v3").await {
        Ok(status) => {
            println!("   Subgraph: {}", status.subgraph_id);
            println!("   Synced block: {}", status.synced_block);
            println!("   Target block: {}", status.target_block);
            println!("   Progress: {:.2}%", status.progress_percentage);
            println!("   Status: {}", status.status);
            if let Some(error) = status.last_error {
                println!("   Last error: {}", error);
            }
        }
        Err(e) => println!("   Note: {}\n", e),
    }

    // 5. List indexers
    println!("\n5. Listing indexers...");
    match client.indexing().list_indexers().await {
        Ok(indexers) => {
            if indexers.is_empty() {
                println!("   No indexers registered yet");
            } else {
                println!("   Found {} indexers:", indexers.len());
                for indexer in &indexers {
                    println!("   - {}", indexer.indexer_did);
                    println!("     Stake: {} CAN", indexer.stake_amount);
                    println!("     Status: {:?}", indexer.status);
                    println!("     Performance: {:.1}", indexer.performance_score);
                    println!("     Subgraphs: {:?}", indexer.subgraphs);
                }
            }
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 6. Get verification stats
    println!("\n6. Getting verification stats...");
    match client.indexing().get_verification_stats().await {
        Ok(stats) => {
            println!("   Total blocks: {}", stats.total_blocks);
            println!("   Verified blocks: {}", stats.verified_blocks);
            println!("   Unverified blocks: {}", stats.unverified_blocks);
            println!("   Finalized blocks: {}", stats.finalized_blocks);
            println!("   Failed blocks: {}", stats.failed_blocks);
            println!("   Verification rate: {:.2}%", stats.verification_rate * 100.0);
        }
        Err(e) => println!("   Note: {}", e),
    }

    // 7. Comparison with The Graph
    println!("\n7. Willow vs The Graph...");
    println!("   Willow advantages:");
    println!("   + 50-100x faster query performance");
    println!("   + Cryptographic proofs for every query");
    println!("   + No fisherman disputes needed");
    println!("   + Instant finality on results");
    println!("   + Native proof verification in SDK");

    println!("\nGraphQL indexing example complete!");
    Ok(())
}
