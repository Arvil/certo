// This file is part of the `certo` project.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to initialise TLS context: {why}")]
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

    #[error("No certificate was presented by the server.")]
    NoCertificate,

    #[error("Could not connect to {hostname}:{port}: {why}")]
    ConnectionFailure {
        hostname: String,
        port: u16,
        why: String,
    },

    #[error("TLS handshake with {hostname}:{port} did not complete within {seconds} seconds")]
    HandshakeTimeout {
        hostname: String,
        port: u16,
        seconds: u64,
    },

    #[error("Invalid hostname: {hostname} ({why})")]
    InvalidHostname { hostname: String, why: String },

    #[error("Failed to load certificates from {path}: {why}")]
    CertificateLoadFailure { path: String, why: String },

    #[error("Some ({0}) tests failed")]
    CertoTestFailure(usize),
}
