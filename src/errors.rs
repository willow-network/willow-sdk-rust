//! Error types for Willow SDK

use thiserror::Error;

/// Result type alias for Willow operations
pub type Result<T> = std::result::Result<T, WillowError>;

/// Main error type for Willow SDK
#[derive(Error, Debug)]
pub enum WillowError {
    /// Network-related errors
    #[error("Network error: {0}")]
    Network(String),

    /// HTTP request failed
    #[error("HTTP error (status {status}): {message}")]
    Http { status: u16, message: String },

    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Not authenticated
    #[error("Not authenticated. Please call set_identity() first")]
    NotAuthenticated,

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    /// Light client error
    #[error("Light client error: {0}")]
    LightClient(String),

    /// Historical data unavailable
    #[error("Historical data unavailable: {message}")]
    HistoricalDataUnavailable { message: String, can_reindex: bool },

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic error with custom message
    #[error("{0}")]
    Custom(String),
}

impl From<reqwest::Error> for WillowError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            WillowError::Network("Request timed out".to_string())
        } else if err.is_connect() {
            WillowError::Network(format!("Failed to connect: {}", err))
        } else if let Some(status) = err.status() {
            WillowError::Http {
                status: status.as_u16(),
                message: err.to_string(),
            }
        } else {
            WillowError::Network(err.to_string())
        }
    }
}

impl From<hex::FromHexError> for WillowError {
    fn from(err: hex::FromHexError) -> Self {
        WillowError::Validation(format!("Invalid hex: {}", err))
    }
}

impl From<ed25519_dalek::ed25519::Error> for WillowError {
    fn from(_: ed25519_dalek::ed25519::Error) -> Self {
        WillowError::InvalidSignature
    }
}

impl From<url::ParseError> for WillowError {
    fn from(err: url::ParseError) -> Self {
        WillowError::Config(format!("Invalid URL: {}", err))
    }
}

impl From<secp256k1::Error> for WillowError {
    fn from(err: secp256k1::Error) -> Self {
        WillowError::Crypto(format!("Secp256k1 error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Error Display Tests
    // ========================================================================

    #[test]
    fn test_network_error_display() {
        let err = WillowError::Network("Connection refused".to_string());
        assert_eq!(err.to_string(), "Network error: Connection refused");
    }

    #[test]
    fn test_http_error_display() {
        let err = WillowError::Http {
            status: 404,
            message: "Not found".to_string(),
        };
        assert_eq!(err.to_string(), "HTTP error (status 404): Not found");
    }

    #[test]
    fn test_authentication_error_display() {
        let err = WillowError::Authentication("Invalid credentials".to_string());
        assert_eq!(err.to_string(), "Authentication error: Invalid credentials");
    }

    #[test]
    fn test_not_authenticated_display() {
        let err = WillowError::NotAuthenticated;
        assert!(err.to_string().contains("Not authenticated"));
    }

    #[test]
    fn test_validation_error_display() {
        let err = WillowError::Validation("Field required".to_string());
        assert_eq!(err.to_string(), "Validation error: Field required");
    }

    #[test]
    fn test_not_found_error_display() {
        let err = WillowError::NotFound("Document abc123".to_string());
        assert_eq!(err.to_string(), "Resource not found: Document abc123");
    }

    #[test]
    fn test_permission_denied_display() {
        let err = WillowError::PermissionDenied("Write access required".to_string());
        assert_eq!(err.to_string(), "Permission denied: Write access required");
    }

    #[test]
    fn test_crypto_error_display() {
        let err = WillowError::Crypto("Invalid key length".to_string());
        assert_eq!(err.to_string(), "Cryptographic error: Invalid key length");
    }

    #[test]
    fn test_invalid_signature_display() {
        let err = WillowError::InvalidSignature;
        assert_eq!(err.to_string(), "Invalid signature");
    }

    #[test]
    fn test_proof_verification_failed_display() {
        let err = WillowError::ProofVerificationFailed("Root hash mismatch".to_string());
        assert_eq!(
            err.to_string(),
            "Proof verification failed: Root hash mismatch"
        );
    }

    #[test]
    fn test_light_client_error_display() {
        let err = WillowError::LightClient("Header verification failed".to_string());
        assert_eq!(
            err.to_string(),
            "Light client error: Header verification failed"
        );
    }

    #[test]
    fn test_config_error_display() {
        let err = WillowError::Config("Invalid chain ID".to_string());
        assert_eq!(err.to_string(), "Configuration error: Invalid chain ID");
    }

    #[test]
    fn test_custom_error_display() {
        let err = WillowError::Custom("Something went wrong".to_string());
        assert_eq!(err.to_string(), "Something went wrong");
    }

    // ========================================================================
    // Error Conversion Tests
    // ========================================================================

    #[test]
    fn test_from_serde_json_error() {
        let json_result: std::result::Result<serde_json::Value, _> =
            serde_json::from_str("invalid json");
        let err: WillowError = json_result.unwrap_err().into();
        assert!(matches!(err, WillowError::Serialization(_)));
    }

    #[test]
    fn test_from_hex_error() {
        let hex_err = hex::decode("invalid_hex").unwrap_err();
        let err: WillowError = hex_err.into();
        assert!(matches!(err, WillowError::Validation(_)));
        assert!(err.to_string().contains("Invalid hex"));
    }

    #[test]
    fn test_from_url_parse_error() {
        let url_err = url::Url::parse("not a url").unwrap_err();
        let err: WillowError = url_err.into();
        assert!(matches!(err, WillowError::Config(_)));
        assert!(err.to_string().contains("Invalid URL"));
    }

    // ========================================================================
    // Error Debug Tests
    // ========================================================================

    #[test]
    fn test_error_is_debug() {
        let err = WillowError::Custom("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Custom"));
        assert!(debug_str.contains("test"));
    }

    // ========================================================================
    // Result Type Tests
    // ========================================================================

    #[test]
    fn test_result_ok() {
        let result: Result<i32> = Ok(42);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_result_err() {
        let result: Result<i32> = Err(WillowError::NotAuthenticated);
        assert!(result.is_err());
    }
}
