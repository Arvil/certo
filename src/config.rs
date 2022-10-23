use log::{info, warn};
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

pub fn load_root_certs() -> RootCertStore {
    let mut root_store = rustls::RootCertStore::empty();

    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                root_store.add(&rustls::Certificate(cert.0)).unwrap();
            }
            info!("Loaded native root certificate store.");
        }
        Err(_) => {
            // Fallback to webpki_roots
            warn!("Failed to load native root certificate store, falling back to WebPKI...");
            load_webpki_roots(&mut root_store);
        }
    }
    root_store
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
