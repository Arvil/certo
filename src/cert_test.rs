use std::sync::Arc;

use rustls::ClientConfig;
use serde::{ser::SerializeStruct, Serialize};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{cert, error::Error, types::DaysToExpiration};

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
        let mut state = serializer.serialize_struct("CertTest", 3)?;
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
    pub fn new(
        hostname: &'a str,
        days_to_expiration: i64,
        ssl_config: Arc<ClientConfig>,
    ) -> CertTest<'a> {
        let server_name = match hostname.to_string().try_into() {
            Ok(sn) => sn,
            Err(e) => return CertTest {
                hostname,
                result: Err(Error::InvalidHostname {
                    hostname: hostname.to_string(),
                    details: format!("{}", e)
                }),
            },
        };

        let mut conn = match rustls::ClientConnection::new(ssl_config, server_name) {
            Ok(conn) => conn,
            Err(e) => return CertTest {
                hostname,
                result: Err(Error::TLSInitializationFailure {
                    why: format!("Failed to create TLS connection for '{}': {}", hostname, e)
                }),
            },
        };

        match cert::get_cert_chain(&mut conn, hostname) {
            Err(e) => CertTest {
                hostname,
                result: Err(e),
            },
            Ok(chain) => {
                let leaf_der = match chain.first() {
                    Some(cert) => cert.as_ref(),
                    None => return CertTest {
                        hostname,
                        result: Err(Error::NoCertificate),
                    },
                };

                let certificate = match X509Certificate::from_der(leaf_der) {
                    Ok((_, leaf_cert)) => leaf_cert,
                    Err(e) => return CertTest {
                        hostname,
                        result: Err(Error::InvalidCertificate {
                            why: format!("Failed to parse certificate: {}", e)
                        }),
                    },
                };

                let not_after = &certificate
                    .tbs_certificate
                    .validity()
                    .not_after
                    .to_datetime();
                let now = OffsetDateTime::now_utc();

                CertTest {
                    hostname,
                    result: {
                        let remaining_days = (*not_after - now).whole_days();
                        if remaining_days > days_to_expiration {
                            Ok(DaysToExpiration(remaining_days))
                        } else {
                            Err(Error::AlmostExpiredCertificate {
                                days_to_expiration: remaining_days,
                                max_days_to_expiration: days_to_expiration,
                            })
                        }
                    },
                }
            }
        }
    }
}
