// This file is part of the `certo` project.

use std::{fs::File, io::BufReader, path::PathBuf};

use log::{debug, error, warn};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{pem::PemObject, CertificateDer};

use crate::{
    client_auth::ClientAuthenticationCredentials,
    error::{Error, Result},
};

/// Populate `store` with the operating system's root certificates.
///
/// Unparsable certificates are logged and skipped.
pub fn load_native_certs(store: &mut RootCertStore) -> Result<()> {
    let native_certs = rustls_native_certs::load_native_certs();

    let mut added = 0;
    for cert in native_certs.certs {
        match store.add(cert) {
            Ok(()) => added += 1,
            Err(e) => error!("Ignoring unparsable certificate from the system store: {e}"),
        }
    }
    if added == 0 {
        warn!("No usable certificates were found in the system root store");
    }
    Ok(())
}

/// Populate `store` with the bundled Mozilla root certificate set.
pub fn load_webpki_roots(store: &mut RootCertStore) {
    for ta in webpki_roots::TLS_SERVER_ROOTS.iter() {
        store.roots.push(ta.clone());
    }
}

/// Load PEM certificates from `paths` into `store`, returning the number of
/// certificates added.
///
/// A path that cannot be read, or that yields no certificates at all, is a
/// hard error: explicitly named trust anchors must not fail silently.
/// Unparsable entries inside an otherwise valid file are logged and skipped.
pub fn load_pem_certs(store: &mut RootCertStore, paths: &[PathBuf]) -> Result<usize> {
    let mut total = 0;
    for path in paths {
        let file = File::open(path).map_err(|e| Error::CertificateLoadFailure {
            path: path.display().to_string(),
            why: format!("cannot open file: {e}"),
        })?;
        let reader = BufReader::new(file);

        let mut added = 0;
        for maybe_cert in CertificateDer::pem_reader_iter(reader) {
            match maybe_cert {
                Ok(cert) => match store.add(cert) {
                    Ok(()) => added += 1,
                    Err(e) => error!("Ignoring unparsable certificate in {}: {e}", path.display()),
                },
                Err(e) => error!("Ignoring unparsable PEM entry in {}: {e}", path.display()),
            }
        }

        if added == 0 {
            return Err(Error::CertificateLoadFailure {
                path: path.display().to_string(),
                why: "no certificates found in file".to_string(),
            });
        }
        debug!("Loaded {added} certificate(s) from {}", path.display());
        total += added;
    }
    Ok(total)
}

/// Build a [`ClientConfig`] from `root_store`, optionally with client
/// authentication credentials.
pub fn safe_clientconfig(
    root_store: RootCertStore,
    client_auth: Option<ClientAuthenticationCredentials<'static>>,
) -> Result<ClientConfig> {
    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

    let config = match client_auth {
        Some(creds) => builder.with_client_auth_cert(creds.cert_chain, creds.key_der),
        None => Ok(builder.with_no_client_auth()),
    };

    config.map_err(|e| Error::TLSInitializationFailure { why: e.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names
            .iter()
            .map(|n| PathBuf::from("tests/certs").join(n))
            .collect()
    }

    #[test]
    fn test_load_pem_certs() {
        let mut store = RootCertStore::empty();
        let added = load_pem_certs(&mut store, &paths(&["isrgrootx1.pem"])).unwrap();
        assert_eq!(added, 1);
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
        let err = load_pem_certs(&mut store, &paths(&["ca.cert.pem.non_existent"])).unwrap_err();
        assert!(
            err.to_string().contains("cannot open file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_load_pem_certs_multiple_certs() {
        let mut store = RootCertStore::empty();
        let added = load_pem_certs(
            &mut store,
            &paths(&[
                "isrgrootx1.pem",
                "lets-encrypt-r3.pem",
                "expired-isrgrootx1-letsencrypt-org.pem",
            ]),
        )
        .unwrap();
        assert_eq!(added, 3);
        assert_eq!(store.roots.len(), 3);
    }

    #[test]
    fn test_load_pem_certs_invalid_cert_multiple_certs() {
        // A file with no certificates at all is a hard error, even when other
        // files in the same invocation were fine.
        let mut store = RootCertStore::empty();
        let err = load_pem_certs(
            &mut store,
            &paths(&["isrgrootx1.pem", "lets-encrypt-r3.pem", "invalid.cert.pem"]),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("no certificates found in file"),
            "unexpected error: {err}"
        );
        // The valid files were still loaded before the failure.
        assert_eq!(store.roots.len(), 2);
    }

    #[test]
    fn test_load_pem_certs_empty_file() {
        let mut store = RootCertStore::empty();
        let err = load_pem_certs(&mut store, &paths(&["empty.pem"])).unwrap_err();
        assert!(
            err.to_string().contains("no certificates found in file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_load_webpki_roots() {
        let mut store = RootCertStore::empty();
        load_webpki_roots(&mut store);
        assert_ne!(store.roots.len(), 0);
    }
}
