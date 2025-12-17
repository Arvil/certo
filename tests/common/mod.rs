use serde::{ser::SerializeStruct, Serialize};

#[derive(Debug)]
pub struct CertTest<'a> {
    pub hostname: &'a str,
    pub result: Result<DaysToExpiration, Error>,
}

impl Serialize for CertTest<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("CertTest", 4)?;
        state.serialize_field("hostname", self.hostname)?;

        let (maybe_remaining_days, result_str) = match &self.result {
            Ok(days_to_expiration) => (
                Some(days_to_expiration),
                format!("{} days remaining", days_to_expiration),
            ),
            Err(err) => (None, err.to_string()),
        };
        state.serialize_field("success", &self.result.is_ok())?;
        state.serialize_field("message", &result_str)?;
        state.serialize_field("remainingDays", &maybe_remaining_days)?;
        state.end()
    }
}

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct DaysToExpiration(pub i64);

impl std::fmt::Display for DaysToExpiration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidHostname { hostname: String, details: String },
    ConnectionFailure { hostname: String, details: String },
    InvalidCertificate { why: String },
    AlmostExpiredCertificate { days_to_expiration: i64, max_days_to_expiration: i64 },
    NoCertificate,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidHostname { hostname, details } => write!(f, "Invalid hostname: {} - {}", hostname, details),
            Error::ConnectionFailure { hostname, details } => write!(f, "Could not connect to host {}: {}", hostname, details),
            Error::InvalidCertificate { why } => write!(f, "Invalid Certificate: {}.", why),
            Error::AlmostExpiredCertificate { days_to_expiration, max_days_to_expiration } => write!(f, "Certificate about to expire in {} days < {}", days_to_expiration, max_days_to_expiration),
            Error::NoCertificate => write!(f, "No certificate was found."),
        }
    }
}

pub fn create_mock_certificate_with_expiration_days(days: i64) -> MockCertificate {
    MockCertificate {
        expiration_days: days,
    }
}

pub struct MockCertificate {
    pub expiration_days: i64,
}

pub fn test_expiration_logic(cert: &MockCertificate, threshold_days: i64) -> Result<DaysToExpiration, Error> {
    let remaining_days = cert.expiration_days;

    if remaining_days > threshold_days {
        Ok(DaysToExpiration(remaining_days))
    } else {
        Err(Error::AlmostExpiredCertificate {
            days_to_expiration: remaining_days,
            max_days_to_expiration: threshold_days,
        })
    }
}