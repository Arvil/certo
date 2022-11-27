use std::sync::Arc;

use clap::Parser;
use error::{Error, Result};
use log::{debug, error, info};
use rayon::prelude::*;

use crate::{cert_test::CertTest, cli::Args, client_auth::ClientAuthenticationCredentials};

mod cert;
mod cert_test;
mod cli;
mod client_auth;
mod error;
mod ssl_config;
mod types;

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    debug!("Config: {:#?}", args);

    let mut root_store = rustls::RootCertStore::empty();

    if args.custom_ca_certs.is_empty() {
        ssl_config::load_native_certs(&mut root_store)?;
    } else {
        ssl_config::load_pem_certs(&mut root_store, args.custom_ca_certs);
        if args.force_system_root_store {
            ssl_config::load_native_certs(&mut root_store)?;
        }
    }

    let client_auth = if args.client_keyfile.is_some() && !args.client_cert_chain.is_empty() {
        Some(ClientAuthenticationCredentials::new(
            &args.client_cert_chain,
            &args.client_keyfile.unwrap(),
        )?)
    } else {
        None
    };

    let config = Arc::new(ssl_config::safe_clientconfig(root_store, client_auth)?);

    let tests: Vec<_> = args
        .hosts
        .par_iter()
        .map(|hostname| CertTest::new(hostname, args.days_to_expiration, config.clone()))
        .collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&tests).unwrap());
    } else {
        tests.iter().for_each(|t| match &t.result {
            Ok(remaining_days) => {
                info!("[ PASS ] {}: {} days remaining", t.hostname, remaining_days)
            }
            Err(e) => error!("[ FAIL ] {}: {}", t.hostname, e),
        })
    }

    if tests.iter().all(|t| t.result.is_ok()) {
        Ok(())
    } else {
        Err(Error::CertoTestFailure(1))
    }
}
