use std::{path::PathBuf, fs};

use log::{info, warn, error};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, Certificate};

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

pub fn load_certs(store: &mut RootCertStore, certs: Vec<PathBuf>) {
    
    for cert in certs.iter() {
        if let Ok(der) = fs::read(cert) {
            match store.add(&Certificate(der)) {
                Ok(_) => info!("Loaded {}", cert.to_string_lossy()),
                Err(e) => error!("Failed to import {}: {}", cert.to_string_lossy(), e.to_string()),
            }
        } else {
            error!("Failed to read {}", cert.to_string_lossy());
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
