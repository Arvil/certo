// This file is part of the `certo` project.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rayon::prelude::*;
use rustls::RootCertStore;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

use certo::{
    cert_test::CertTest,
    cli::{Args, DEFAULT_TLS_PORT},
    client_auth::ClientAuthenticationCredentials,
    error::{Error, Result},
    ssl_config,
};

fn main() -> Result<()> {
    // Surface [ PASS ] and [ FAIL ] lines by default; RUST_LOG still controls
    // the level for CI setups that want quieter or noisier output.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    log::debug!("Config: {:#?}", args);

    let root_store = build_root_store(&args)?;
    let client_auth = load_client_auth(&args)?;
    let config = Arc::new(ssl_config::safe_clientconfig(root_store, client_auth)?);

    let timeout = Duration::from_secs(args.timeout_seconds);
    let tests: Vec<_> = args
        .hosts
        .par_iter()
        .map(|spec| {
            CertTest::new(
                spec,
                DEFAULT_TLS_PORT,
                args.days_to_expiration,
                config.clone(),
                timeout,
            )
        })
        .collect();

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&tests).expect("results serialize")
        );
    } else {
        tests.iter().for_each(|t| match &t.result {
            Ok(remaining_days) => {
                log::info!("[ PASS ] {}: {} days remaining", t.hostname, remaining_days)
            }
            Err(e) => log::error!("[ FAIL ] {}: {}", t.hostname, e),
        });
    }

    let failures = tests.iter().filter(|t| t.result.is_err()).count();
    if failures == 0 {
        Ok(())
    } else {
        Err(Error::CertoTestFailure(failures))
    }
}

/// Compose the root certificate store from the requested sources.
///
/// * the system store is used unless `--webpki-roots` replaces it,
/// * `--webpki-roots` adds the bundled Mozilla root set,
/// * `--custom-ca-certs` are always added,
/// * `--force-system-root-store` re-adds the system store on top of any
///   custom certificates.
fn build_root_store(args: &Args) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();

    let use_native =
        (args.custom_ca_certs.is_empty() && !args.webpki_roots) || args.force_system_root_store;
    if use_native {
        ssl_config::load_native_certs(&mut store)?;
    }
    if args.webpki_roots {
        ssl_config::load_webpki_roots(&mut store);
    }
    if !args.custom_ca_certs.is_empty() {
        ssl_config::load_pem_certs(&mut store, &args.custom_ca_certs)?;
    }

    if store.is_empty() {
        return Err(Error::TLSInitializationFailure {
            why: "no usable root certificates available; provide CA certificates with -c, \
                  or use -w to use the bundled root store"
                .to_string(),
        });
    }
    Ok(store)
}

/// Validate and load the optional client authentication credentials.
///
/// The certificate chain and the keyfile must be supplied together.
fn load_client_auth(args: &Args) -> Result<Option<ClientAuthenticationCredentials<'static>>> {
    match (
        args.client_cert_chain.as_slice(),
        args.client_keyfile.as_ref(),
    ) {
        ([], None) => Ok(None),
        (chain, Some(keyfile)) => Ok(Some(load_client_auth_credentials(chain, keyfile)?)),
        (chain, None) => Err(Error::InvalidCredentials {
            why: format!(
                "--client-keyfile is required when --client-cert-chain is given (got {} file(s))",
                chain.len()
            ),
        }),
    }
}

fn load_client_auth_credentials(
    chain_paths: &[std::path::PathBuf],
    key_path: &Path,
) -> Result<ClientAuthenticationCredentials<'static>> {
    let mut cert_chain = Vec::new();
    for path in chain_paths {
        for maybe_cert in
            CertificateDer::pem_file_iter(path).map_err(|e| Error::CertificateLoadFailure {
                path: path.display().to_string(),
                why: e.to_string(),
            })?
        {
            let cert = maybe_cert.map_err(|e| Error::CertificateLoadFailure {
                path: path.display().to_string(),
                why: e.to_string(),
            })?;
            cert_chain.push(cert);
        }
    }

    if cert_chain.is_empty() {
        return Err(Error::CertificateLoadFailure {
            path: chain_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            why: "no certificates found".to_string(),
        });
    }

    let key_der = PrivateKeyDer::from_pem_file(key_path).map_err(|e| Error::InvalidPrivateKey {
        why: format!("{}: {}", key_path.display(), e),
    })?;

    Ok(ClientAuthenticationCredentials {
        cert_chain,
        key_der,
    })
}
