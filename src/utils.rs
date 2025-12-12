//! Utility functions for Willow SDK

use std::time::Duration;
use uuid::Uuid;

/// Generate a unique ID with optional prefix
pub fn generate_id(prefix: Option<&str>) -> String {
    let id = Uuid::new_v4().to_string().replace("-", "")[..12].to_string();
    match prefix {
        Some(p) => format!("{}_{}", p, id),
        None => id,
    }
}

/// Parse API URL and ensure it's valid
pub fn parse_api_url(url: &str) -> Result<url::Url, crate::errors::WillowError> {
    let mut url = url.trim_end_matches('/').to_string();

    // Add protocol if missing
    if !url.starts_with("http://") && !url.starts_with("https://") {
        url = format!("http://{}", url);
    }

    url::Url::parse(&url)
        .map_err(|e| crate::errors::WillowError::Config(format!("Invalid API URL: {}", e)))
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub exponential_base: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            exponential_base: 2.0,
        }
    }
}

/// Calculate exponential backoff delay
pub fn calculate_backoff(attempt: u32, config: &RetryConfig) -> Duration {
    let delay_ms =
        config.initial_delay.as_millis() as f64 * config.exponential_base.powi(attempt as i32);
    let delay_ms = delay_ms.min(config.max_delay.as_millis() as f64) as u64;
    Duration::from_millis(delay_ms)
}

/// Validate DID format
pub fn validate_did(did: &str) -> bool {
    did.starts_with("did:willow:") && did.split(':').count() >= 4
}

/// Validate hex string
pub fn validate_hex_string(hex_str: &str, expected_length: Option<usize>) -> bool {
    if let Ok(bytes) = hex::decode(hex_str) {
        if let Some(len) = expected_length {
            bytes.len() == len
        } else {
            true
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id() {
        let id1 = generate_id(None);
        let id2 = generate_id(None);
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 12);

        let id_with_prefix = generate_id(Some("test"));
        assert!(id_with_prefix.starts_with("test_"));
    }

    #[test]
    fn test_parse_api_url() {
        let url = parse_api_url("http://localhost:3031").unwrap();
        assert_eq!(url.host_str(), Some("localhost"));
        assert_eq!(url.port(), Some(3031));

        let url = parse_api_url("localhost:3031").unwrap();
        assert_eq!(url.scheme(), "http");

        let url = parse_api_url("https://api.willow.dev/").unwrap();
        assert_eq!(url.scheme(), "https");
    }

    #[test]
    fn test_validate_did() {
        assert!(validate_did("did:willow:ed25519:abc123"));
        assert!(validate_did("did:willow:secp256k1:def456"));
        assert!(!validate_did("did:other:method:123"));
        assert!(!validate_did("not-a-did"));
    }

    #[test]
    fn test_validate_hex_string() {
        assert!(validate_hex_string("abcdef123456", None));
        assert!(validate_hex_string("00112233", Some(4)));
        assert!(!validate_hex_string("00112233", Some(5)));
        assert!(!validate_hex_string("xyz", None));
    }
}
