use std::{
    fs::File,
    io::BufReader,
    path::PathBuf,
};

use log::{error, info, warn};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

fn load_webpki_roots(store: &mut RootCertStore) {
    store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }))
}

pub fn load_root_certs(store: &mut RootCertStore) {
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                store.add(&rustls::Certificate(cert.0)).unwrap();
            }
            info!("Loaded native root certificate store.");
        }
        Err(_) => {
            // Fallback to webpki_roots
            warn!("Failed to load native root certificate store, falling back to WebPKI...");
            load_webpki_roots(store);
        }
    }
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

pub fn safe_clientconfig(root_store: RootCertStore) -> ClientConfig {
    rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}
