use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to initialize TLS context: {why}")]
    TLSInitializationFailure { why: String },

    #[error("Invalid Certificate: {why}.")]
    InvalidCertificate { why: String },

    #[error("Invalid Private Key: {why}.")]
    InvalidPrivateKey { why: String },

    #[error("Invalid Credentials: {why}.")]
    InvalidCredentials { why: String },

    #[error("Certificate about to expire in {days_to_expiration} days < {max_days_to_expiration}")]
    AlmostExpiredCertificate {
        days_to_expiration: i64,
        max_days_to_expiration: i64,
    },

    #[error("No certificate was found.")]
    NoCertificate,

    #[error("Could not connect to host {hostname}: {details}")]
    ConnectionFailure { hostname: String, details: String },

    #[error("Some ({0}) tests failed")]
    CertoTestFailure(usize),

    #[error("Invalid hostname: {hostname} - {details}")]
    InvalidHostname { hostname: String, details: String },

    #[error("JSON serialization failed: {why}")]
    JsonSerializationFailure { why: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_formats() {
        let error_cases = vec![
            (
                Error::InvalidHostname {
                    hostname: "bad host".to_string(),
                    details: "invalid characters".to_string(),
                },
                "Invalid hostname: bad host - invalid characters",
            ),
            (
                Error::ConnectionFailure {
                    hostname: "example.com".to_string(),
                    details: "timeout".to_string(),
                },
                "Could not connect to host example.com: timeout",
            ),
            (
                Error::InvalidCertificate {
                    why: "malformed".to_string(),
                },
                "Invalid Certificate: malformed.",
            ),
            (
                Error::AlmostExpiredCertificate {
                    days_to_expiration: 2,
                    max_days_to_expiration: 30,
                },
                "Certificate about to expire in 2 days < 30",
            ),
            (Error::NoCertificate, "No certificate was found."),
            (Error::CertoTestFailure(5), "Some (5) tests failed"),
            (
                Error::JsonSerializationFailure {
                    why: "io error".to_string(),
                },
                "JSON serialization failed: io error",
            ),
        ];

        for (error, expected_display) in error_cases {
            assert_eq!(error.to_string(), expected_display);
        }
    }

    #[test]
    fn test_error_debug_formats() {
        let error = Error::InvalidHostname {
            hostname: "test".to_string(),
            details: "details".to_string(),
        };
        let debug_output = format!("{:?}", error);
        assert!(debug_output.contains("InvalidHostname"));
        assert!(debug_output.contains("test"));
        assert!(debug_output.contains("details"));
    }
}
