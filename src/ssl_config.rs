use std::{fs::File, io::BufReader, path::PathBuf};

use log::{error, info};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

use crate::client_auth::ClientAuthenticationCredentials;

#[allow(dead_code)] // will be used in later versions
fn load_webpki_roots(store: &mut RootCertStore) {
    store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }))
}

pub fn load_native_certs(store: &mut RootCertStore) -> crate::Result<()> {
    let native_certs = rustls_native_certs::load_native_certs()
        .map_err(|e| crate::Error::TLSInitializationFailure { why: e.to_string() })?;

    for cert in native_certs {
        if let Err(crate::Error::InvalidCertificate { why }) = store
            .add(&rustls::Certificate(cert.0))
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

            match rustls_pemfile::certs(&mut f) {
                Ok(contents) => {
                    let (added, ignored) = store.add_parsable_certificates(&contents);
                    info!(
                        "Added {} and ignored {} certificates from {}",
                        added,
                        ignored,
                        ca_cert.to_string_lossy()
                    );
                }
                Err(_) => error!("Failed to parse {}", ca_cert.to_string_lossy()),
            }
        } else {
            error!("Failed to read {}", ca_cert.to_string_lossy());
        }
    }
}

pub fn safe_clientconfig(
    root_store: RootCertStore,
    client_auth: Option<ClientAuthenticationCredentials>,
) -> crate::Result<ClientConfig> {
    let wants_client_auth = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .map_err(|e| crate::Error::TLSInitializationFailure { why: e.to_string() })?
        .with_root_certificates(root_store);

    match client_auth {
        Some(creds) => wants_client_auth
            .with_single_cert(creds.cert_chain, creds.key_der)
            .map_err(|e| crate::Error::InvalidCredentials { why: e.to_string() }),
        None => Ok(wants_client_auth.with_no_client_auth()),
    }
}
