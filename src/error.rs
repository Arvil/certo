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
