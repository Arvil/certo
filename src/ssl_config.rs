use std::{fs::File, io::BufReader, path::PathBuf};

use log::error;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;

use crate::client_auth::ClientAuthenticationCredentials;


#[allow(dead_code)] // will be used in later versions
fn load_webpki_roots(store: &mut RootCertStore) {
    for ta in webpki_roots::TLS_SERVER_ROOTS.iter() {
        store.roots.push(ta.clone());
    }
}

pub fn load_native_certs(store: &mut RootCertStore) -> crate::Result<()> {
    let native_certs = rustls_native_certs::load_native_certs();

    for cert in native_certs.certs {
        if let Err(crate::Error::InvalidCertificate { why }) = store
            .add(CertificateDer::from(cert))
            .map_err(|e| crate::Error::InvalidCertificate { why: e.to_string() })
        {
            error!(
                "Failed to add certificate from native certificate store: {}",
                why
            );
        }
    }
    Ok(())
}

pub fn load_pem_certs(store: &mut RootCertStore, certs: Vec<PathBuf>) {
    for ca_cert in certs.iter() {
        if let Ok(f) = File::open(ca_cert) {
            let mut f = BufReader::new(f);

            for maybe_cert in rustls_pemfile::certs(&mut f) {
                if let Ok(cert) = maybe_cert {
                    if let Err(e) = store.add(cert) {
                        error!("Failed to add certificate: {}", e);
                    } else {
                        error!("Failed to read certificate from {}", ca_cert.to_string_lossy());
                    }
                } else {
                    error!("Failed to read certificate from {}", ca_cert.to_string_lossy());
                }
            }
        } else {
            error!("Failed to read {}", ca_cert.to_string_lossy());
        }
    }
}

pub fn safe_clientconfig(
    root_store: RootCertStore,
    client_auth: Option<ClientAuthenticationCredentials<'static>>,
) -> crate::Result<ClientConfig> {
    let wants_client_auth = rustls::ClientConfig::builder()
        .with_root_certificates(root_store);

    let config = match client_auth {
        Some(creds) => {
            wants_client_auth
                .with_client_auth_cert(creds.cert_chain, creds.key_der)
                .map_err(|e| crate::Error::InvalidCertificate { why: e.to_string() })
        }
        None => Ok(wants_client_auth.with_no_client_auth()),
    };

    config.map_err(move |e| crate::Error::InvalidCertificate { why: e.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_pem_certs() {
        let mut store = RootCertStore::empty();
        let certs = vec![PathBuf::from("tests/certs/isrgrootx1.pem")];
        load_pem_certs(&mut store, certs);
        assert_eq!(store.roots.len(), 1);
    }

    #[test]
    fn test_load_native_certs() {
        let mut store = RootCertStore::empty();
        load_native_certs(&mut store).unwrap();
        assert_ne!(store.roots.len(), 0);
    }

    #[test]
    fn test_load_pem_certs_non_existent_file() {
        let mut store = RootCertStore::empty();
        let certs = vec![PathBuf::from("tests/certs/ca.cert.pem.non_existent")];
        load_pem_certs(&mut store, certs);
        assert_eq!(store.roots.len(), 0);
    }

    #[test]
    fn test_load_pem_certs_multiple_certs() {
        let mut store = RootCertStore::empty();
        let certs = vec![
            PathBuf::from("tests/certs/isrgrootx1.pem"),
            PathBuf::from("tests/certs/lets-encrypt-r3.pem"),
            PathBuf::from("tests/certs/expired-isrgrootx1-letsencrypt-org.pem"),
        ];
        load_pem_certs(&mut store, certs);
        assert_eq!(store.roots.len(), 3);
    }

    #[test]
    fn test_load_pem_certs_invalid_cert_multiple_certs() {
        let mut store = RootCertStore::empty();
        let certs = vec![
            PathBuf::from("tests/certs/isrgrootx1.pem"),
            PathBuf::from("tests/certs/lets-encrypt-r3.pem"),
            PathBuf::from("tests/certs/invalid.cert.pem"),
        ];
        load_pem_certs(&mut store, certs);
        assert_eq!(store.roots.len(), 2);
    }
}
