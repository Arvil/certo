use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid Certificate: {why}.")]
    InvalidCertificateError { why: String },
    #[error("Certificate about to expire in {days_to_expiration} days < {max_days_to_expiration}")]
    AlmostExpiredCertificateError {
        days_to_expiration: i64,
        max_days_to_expiration: i64,
    },
    #[error("No certificate was found.")]
    NoCertificateError,
    #[error("Could not connect to host.")]
    ConnectionError,

    #[error("Some ({0}) tests failed")]
    CertoTestFailure(usize),
}
