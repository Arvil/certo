// This file is part of the `certo` project.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use serde::{ser::SerializeStruct, Serialize};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{cert, cli::split_host_port, error::Error, types::DaysToExpiration};

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

impl<'a> CertTest<'a> {
    /// Check the certificate of `spec` (of the form `host[:port]`).
    ///
    /// All failures — including malformed input — are reported as the
    /// [`CertTest::result`] of the returned test; this never panics.
    pub fn new(
        spec: &'a str,
        default_port: u16,
        days_to_expiration: i64,
        ssl_config: Arc<ClientConfig>,
        timeout: Duration,
    ) -> CertTest<'a> {
        let (hostname, port) = match split_host_port(spec, default_port) {
            Ok(parts) => parts,
            Err(e) => {
                return CertTest {
                    hostname: spec,
                    result: Err(e),
                }
            }
        };

        let server_name = match ServerName::try_from(hostname.clone()) {
            Ok(server_name) => server_name,
            Err(e) => {
                return CertTest {
                    hostname: spec,
                    result: Err(Error::InvalidHostname {
                        hostname: hostname.clone(),
                        why: e.to_string(),
                    }),
                };
            }
        };

        let mut conn = match rustls::ClientConnection::new(ssl_config, server_name) {
            Ok(conn) => conn,
            Err(e) => {
                return CertTest {
                    hostname: spec,
                    result: Err(Error::TLSInitializationFailure { why: e.to_string() }),
                };
            }
        };

        let result =
            cert::get_peer_cert_chain(&mut conn, &hostname, port, timeout).and_then(|chain| {
                evaluate_expiry(&chain, OffsetDateTime::now_utc(), days_to_expiration)
            });

        CertTest {
            hostname: spec,
            result,
        }
    }
}

/// Determine the days to expiration of the leaf certificate in `chain`.
///
/// A check passes only when more than `max_days` whole days remain: a
/// certificate expiring within `max_days` days is reported as
/// [`Error::AlmostExpiredCertificate`].
pub fn evaluate_expiry(
    chain: &[rustls_pki_types::CertificateDer<'_>],
    now: OffsetDateTime,
    max_days: i64,
) -> crate::error::Result<DaysToExpiration> {
    let leaf = chain.first().ok_or(Error::NoCertificate)?;

    let (_, certificate) =
        X509Certificate::from_der(leaf.as_ref()).map_err(|e| Error::InvalidCertificate {
            why: format!("could not parse certificate: {e}"),
        })?;

    let not_after = certificate
        .tbs_certificate
        .validity()
        .not_after
        .to_datetime();
    let remaining_days = (not_after - now).whole_days();

    if remaining_days > max_days {
        Ok(DaysToExpiration(remaining_days))
    } else {
        Err(Error::AlmostExpiredCertificate {
            days_to_expiration: remaining_days,
            max_days_to_expiration: max_days,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok_test(remaining: i64) -> CertTest<'static> {
        CertTest {
            hostname: Box::leak("ok.example.com".to_string().into_boxed_str()),
            result: Ok(DaysToExpiration(remaining)),
        }
    }

    fn fail_test(err: Error) -> CertTest<'static> {
        CertTest {
            hostname: Box::leak("fail.example.com".to_string().into_boxed_str()),
            result: Err(err),
        }
    }

    #[test]
    fn test_json_serialization_success() {
        let value = serde_json::to_value(ok_test(42)).unwrap();
        assert_eq!(
            value,
            json!({
                "hostname": "ok.example.com",
                "success": true,
                "message": "42 days remaining",
                "remainingDays": 42,
            })
        );
    }

    #[test]
    fn test_json_serialization_failure() {
        let value = serde_json::to_value(fail_test(Error::NoCertificate)).unwrap();
        assert_eq!(value["hostname"], "fail.example.com");
        assert_eq!(value["success"], false);
        assert_eq!(value["remainingDays"], serde_json::Value::Null);
        assert_eq!(
            value["message"],
            json!("No certificate was presented by the server.")
        );
    }

    #[test]
    fn test_json_serialization_expiring() {
        let err = Error::AlmostExpiredCertificate {
            days_to_expiration: 3,
            max_days_to_expiration: 5,
        };
        let value = serde_json::to_value(fail_test(err)).unwrap();
        assert_eq!(
            value["message"],
            json!("Certificate about to expire in 3 days < 5")
        );
    }

    #[test]
    fn test_evaluate_expiry_passes_beyond_threshold() {
        let now = OffsetDateTime::now_utc();
        // 100 and a half days left: 100 whole days.
        let chain = [test_leaf(
            now + time::Duration::days(100) + time::Duration::hours(12),
        )];
        assert_eq!(
            evaluate_expiry(&chain, now, 99).unwrap(),
            DaysToExpiration(100)
        );
        // The threshold itself is inclusive: exactly `max_days` whole days
        // remaining is "expiring within max_days" and must fail.
        let err = evaluate_expiry(&chain, now, 100).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Certificate about to expire in 100 days < 100"
        );
    }

    #[test]
    fn test_evaluate_expiry_fails_within_threshold() {
        let now = OffsetDateTime::now_utc();
        // 99 and a half days left: 99 whole days.
        let chain = [test_leaf(
            now + time::Duration::days(99) + time::Duration::hours(12),
        )];
        let err = evaluate_expiry(&chain, now, 99).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Certificate about to expire in 99 days < 99"
        );
    }

    #[test]
    fn test_evaluate_expiry_empty_chain() {
        let err = evaluate_expiry(&[], OffsetDateTime::now_utc(), 5).unwrap_err();
        assert_eq!(
            err.to_string(),
            "No certificate was presented by the server."
        );
    }

    #[test]
    fn test_evaluate_expiry_unparsable_der() {
        let chain = [rustls_pki_types::CertificateDer::from(vec![1, 2, 3, 4])];
        let err = evaluate_expiry(&chain, OffsetDateTime::now_utc(), 5).unwrap_err();
        assert!(
            err.to_string().contains("could not parse certificate"),
            "{err}"
        );
    }

    /// A minimal, well-formed DER certificate whose notAfter we control.
    fn test_leaf(not_after: OffsetDateTime) -> rustls_pki_types::CertificateDer<'static> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["leaf.example.com".to_string()]).unwrap();
        params.not_before = not_after - time::Duration::days(30);
        params.not_after = not_after;
        let cert = params.self_signed(&key).unwrap();
        cert.der().clone()
    }
}
