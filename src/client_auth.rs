use std::{fs::File, io::BufReader, path::PathBuf};

use rustls::{Certificate, PrivateKey};

use crate::error;

pub struct ClientAuthenticationCredentials {
    pub cert_chain: Vec<Certificate>,
    pub key_der: PrivateKey,
}

// Todo better error handling
impl ClientAuthenticationCredentials {
    pub fn new(
        cert_chain_paths: &[PathBuf],
        key_path: &PathBuf,
    ) -> crate::Result<ClientAuthenticationCredentials> {
        let mut certs: Vec<Certificate> = Vec::new();
        for cert_path in cert_chain_paths {
            if let Ok(cert_file) = File::open(cert_path) {
                let mut f = BufReader::new(cert_file);
                for cert in rustls_pemfile::certs(&mut f).unwrap_or_default() {
                    certs.push(Certificate(cert));
                }
            } else {
                error!("Failed to read certificate: {}", cert_path.display());
            }
        }

        let key_path_s = key_path.to_string_lossy().to_string();
        let key_der: rustls::PrivateKey = {
            if let Ok(key_file) = File::open(key_path) {
                let mut f = BufReader::new(key_file);
                PrivateKey(
                    rustls_pemfile::pkcs8_private_keys(&mut f)
                        .map_err(|_| crate::Error::InvalidPrivateKey {
                            why: key_path_s.clone(),
                        })?
                        .first()
                        .ok_or(crate::Error::InvalidPrivateKey { why: key_path_s })?
                        .to_owned(),
                )
            } else {
                Err(crate::Error::InvalidPrivateKey { why: key_path_s })?
            }
        };

        Ok(Self {
            cert_chain: certs,
            key_der,
        })
    }
}
