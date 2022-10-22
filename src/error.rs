use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid Certificate: {why}.")]
    InvalidCertificateError {
        why: String,
    },
    #[error("No certificate was found.")]
    NoCertificateError,
    #[error("Could not connect to host.")]
    ConnectionError
}