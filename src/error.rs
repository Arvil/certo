use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Falied to initialise TLS context: {why}")]
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

    #[error("Could not connect to host.")]
    ConnectionFailure,

    #[error("Some ({0}) tests failed")]
    CertoTestFailure(usize),
}
