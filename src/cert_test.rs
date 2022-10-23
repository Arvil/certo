use std::sync::Arc;

use rustls::{ClientConfig, ServerName};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{cert, error::Error};

pub struct CertTest<'a> {
    pub hostname: &'a str,
    pub result: Result<i64, Error>,
}

// Todo serialisation to JSON
impl<'a> CertTest<'a> {
    pub fn new(
        hostname: &'a str,
        days_to_expiration: i64,
        ssl_config: Arc<ClientConfig>,
    ) -> CertTest {
        let server_name: ServerName = hostname.try_into().unwrap();
        let mut conn = rustls::ClientConnection::new(ssl_config.clone(), server_name).unwrap();

        match cert::get_cert_chain(&mut conn, hostname) {
            Ok(chain) => {
                let leaf_der = &chain.first().unwrap().0[..];

                let certificate = {
                    if let Ok((_, leaf_cert)) = X509Certificate::from_der(&leaf_der) {
                        Some(leaf_cert)
                    } else {
                        None
                    }
                }
                .unwrap();

                let not_after = &certificate
                    .tbs_certificate
                    .validity()
                    .not_after
                    .to_datetime();
                let now = OffsetDateTime::now_utc();

                CertTest {
                    hostname: hostname,
                    result: {
                        let remaining_days = (*not_after - now).whole_days();
                        if remaining_days > days_to_expiration {
                            Ok(remaining_days)
                        } else {
                            Err(Error::AlmostExpiredCertificateError {
                                days_to_expiration: remaining_days,
                                max_days_to_expiration: days_to_expiration,
                            })
                        }
                    },
                }
            }
            Err(e) => CertTest {
                hostname: hostname,
                result: Err(e),
            },
        }
    }
}
