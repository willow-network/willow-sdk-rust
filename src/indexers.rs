//! Indexer discovery client for source-routed GraphQL / SQL queries.
//!
//! The SDK's `graphql_query` / `sql_query` methods take a [`QuerySource`]
//! telling the routing layer where the caller wants data served from:
//!
//! - [`QuerySource::Validator`]: consensus-verified chain-tip. Every row is
//!   Merkle-provable. Fails fast for `VerifyOnly` subgroves (validator never
//!   stored the data).
//! - [`QuerySource::Indexer`]: full history + analytics. Trust is
//!   sampling/dispute based.
//! - [`QuerySource::Auto`] (default): indexer when one serves this subgrove,
//!   otherwise validator. On indexer failure, falls back to validator and
//!   sets `fallback: true` in the result.
//!
//! The [`WillowIndexers`] client wraps the validator's `GET /indexers`
//! endpoint with a 30s in-memory cache. When the client is constructed with
//! an explicit `indexer_url`, discovery is bypassed and a synthetic
//! single-entry list is returned so the routing code path stays uniform.
//!
//! Construction is normally handled by the [`WillowClient`][crate::WillowClient]
//! builder; accessing the discovery client directly
//! (via [`WillowClient::indexers`][crate::WillowClient::indexers]) is useful for
//! listing / debugging.
//!
//! # Example
//!
//! ```rust,no_run
//! use willow_sdk::indexers::QuerySource;
//! use willow_sdk::WillowClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = WillowClient::new("http://validator:3031").await?;
//!
//! // Default: auto-route to indexer if any serves the subgrove
//! let routed = client
//!     .indexing()
//!     .graphql_query_with_source("sg-1", "{ ok }", None, QuerySource::Auto)
//!     .await?;
//! println!("served by {:?}, fallback={}", routed.source, routed.fallback);
//! # Ok(()) }
//! ```

use crate::errors::{Result, WillowError};
use crate::types::{ApiResponse, IndexerInfo};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

/// Which backend should serve a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuerySource {
    /// Consensus-verified chain-tip. Fails fast for `VerifyOnly` subgroves.
    Validator,
    /// Full history + analytics via an indexer. Fails if none registered.
    Indexer,
    /// Prefer indexer, fall back to validator. This is the sensible default.
    Auto,
}

impl Default for QuerySource {
    fn default() -> Self {
        QuerySource::Auto
    }
}

/// A query result plus the backend that served it.
///
/// The `source` / `fallback` / `indexer_did` fields make the trust model
/// explicit so callers can display it in a UI or log it.
#[derive(Debug, Clone)]
pub struct RoutedQueryResult<T> {
    /// Raw response from the backend.
    pub result: T,
    /// Which backend actually served this query.
    pub source: ServedBy,
    /// DID of the indexer that served the query. `None` for validator.
    pub indexer_did: Option<String>,
    /// `true` when `Auto` routing fell back from indexer → validator.
    pub fallback: bool,
}

/// Outcome of a routed query — which backend actually served it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServedBy {
    Validator,
    Indexer,
}

/// Default TTL for cached `/indexers` responses.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct CacheEntry {
    data: Vec<IndexerInfo>,
    fetched_at: Instant,
}

/// Discovery client for the validator's `GET /indexers` endpoint.
///
/// Cloning is cheap; the cache is shared across clones via `Arc<Mutex<_>>`.
#[derive(Clone)]
pub struct WillowIndexers {
    http_client: Client,
    api_url: Url,
    indexer_url: Option<Url>,
    cache_ttl: Duration,
    cache: Arc<Mutex<Option<CacheEntry>>>,
}

impl WillowIndexers {
    /// Create a new discovery client.
    pub fn new(http_client: Client, api_url: Url, indexer_url: Option<Url>) -> Self {
        Self::with_cache_ttl(http_client, api_url, indexer_url, DEFAULT_CACHE_TTL)
    }

    /// Create with a custom cache TTL (useful for tests).
    pub fn with_cache_ttl(
        http_client: Client,
        api_url: Url,
        indexer_url: Option<Url>,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            http_client,
            api_url,
            indexer_url,
            cache_ttl,
            cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Was the SDK configured with an explicit indexer URL (bypassing discovery)?
    pub fn has_explicit_override(&self) -> bool {
        self.indexer_url.is_some()
    }

    /// Force the next lookup to re-fetch `/indexers` from the validator.
    pub fn invalidate(&self) {
        if let Ok(mut guard) = self.cache.lock() {
            *guard = None;
        }
    }

    /// Drop a specific indexer from the cache (e.g., after a 5xx response).
    pub fn evict(&self, indexer_did: &str) {
        if let Ok(mut guard) = self.cache.lock() {
            if let Some(entry) = guard.as_mut() {
                entry.data.retain(|i| i.indexer_did != indexer_did);
            }
        }
    }

    /// Return all registered indexers, cached for `cache_ttl`.
    ///
    /// When `indexer_url` is set, returns a synthetic single-entry list
    /// instead of calling the validator.
    pub async fn list(&self) -> Result<Vec<IndexerInfo>> {
        if let Some(url) = &self.indexer_url {
            return Ok(vec![synthetic_entry(url.as_str())]);
        }

        // Cache check without holding the lock across await
        {
            let guard = self.cache.lock().unwrap();
            if let Some(entry) = guard.as_ref() {
                if entry.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(entry.data.clone());
                }
            }
        }

        let url = self
            .api_url
            .join("indexers")
            .map_err(|e| WillowError::Config(format!("Invalid /indexers URL: {}", e)))?;

        let resp = self.http_client.get(url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(WillowError::Http {
                status: status.as_u16(),
                message: text,
            });
        }
        let api: ApiResponse<Vec<IndexerInfo>> =
            serde_json::from_str(&text).map_err(WillowError::Serialization)?;
        let data = api.data.unwrap_or_default();

        if let Ok(mut guard) = self.cache.lock() {
            *guard = Some(CacheEntry {
                data: data.clone(),
                fetched_at: Instant::now(),
            });
        }
        Ok(data)
    }

    /// Return active indexers serving `subgrove_id`, sorted by
    /// `performance_score` descending (best first).
    ///
    /// With an explicit `indexer_url` override, always returns a single
    /// synthetic entry — the routing code doesn't need to special-case this.
    pub async fn for_subgrove(&self, subgrove_id: &str) -> Result<Vec<IndexerInfo>> {
        if let Some(url) = &self.indexer_url {
            return Ok(vec![synthetic_entry(url.as_str())]);
        }

        let mut list: Vec<IndexerInfo> = self
            .list()
            .await?
            .into_iter()
            .filter(|i| {
                matches!(i.status, crate::types::IndexerStatus::Active)
                    && i.subgroves.iter().any(|s| s == subgrove_id)
            })
            .collect();
        list.sort_by(|a, b| {
            b.performance_score
                .partial_cmp(&a.performance_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(list)
    }
}

fn synthetic_entry(url: &str) -> IndexerInfo {
    IndexerInfo {
        indexer_did: "explicit-override".to_string(),
        subgroves: vec![],
        stake_amount: 0,
        endpoint: url.to_string(),
        query_endpoint: Some(url.to_string()),
        status: crate::types::IndexerStatus::Active,
        performance_score: 100.0,
        last_update: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{IndexerInfo, IndexerStatus};

    fn info(did: &str, sgs: Vec<&str>, perf: f64, status: IndexerStatus) -> IndexerInfo {
        IndexerInfo {
            indexer_did: did.to_string(),
            subgroves: sgs.into_iter().map(String::from).collect(),
            stake_amount: 100,
            endpoint: format!("http://{}:9090", did),
            query_endpoint: Some(format!("http://{}:3032", did)),
            status,
            performance_score: perf,
            last_update: 0,
        }
    }

    #[test]
    fn effective_query_endpoint_prefers_query_endpoint() {
        let i = info("x", vec!["sg"], 100.0, IndexerStatus::Active);
        assert_eq!(i.effective_query_endpoint(), "http://x:3032");
    }

    #[test]
    fn effective_query_endpoint_falls_back_to_endpoint() {
        let mut i = info("x", vec!["sg"], 100.0, IndexerStatus::Active);
        i.query_endpoint = None;
        assert_eq!(i.effective_query_endpoint(), "http://x:9090");
    }

    #[test]
    fn query_source_default_is_auto() {
        assert_eq!(QuerySource::default(), QuerySource::Auto);
    }

    #[tokio::test]
    async fn explicit_override_returns_synthetic_entry() {
        let http = Client::new();
        let api_url = Url::parse("http://validator:3031").unwrap();
        let indexer_url = Some(Url::parse("http://pinned:3032").unwrap());
        let disc = WillowIndexers::new(http, api_url, indexer_url);

        assert!(disc.has_explicit_override());
        let all = disc.list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].effective_query_endpoint(), "http://pinned:3032/");
        // `for_subgrove` short-circuits even when the override URL doesn't
        // include the requested subgrove in `subgroves`.
        let picks = disc.for_subgrove("anything").await.unwrap();
        assert_eq!(picks.len(), 1);
    }

    /// When the /indexers call would be needed (no override), we should
    /// surface an error rather than hang if the server is unreachable —
    /// reqwest's default connect timeout + our `Http` error variant covers
    /// this in practice. The test here just validates the shape of the API.
    #[tokio::test]
    async fn invalidate_clears_cache() {
        let http = Client::new();
        let api_url = Url::parse("http://validator:3031").unwrap();
        let disc = WillowIndexers::new(http, api_url, None);
        disc.invalidate(); // should not panic on empty cache
        disc.evict("absent"); // should not panic either
    }
}
