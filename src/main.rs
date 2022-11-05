use std::sync::Arc;

use clap::Parser;
use error::{Error, Result};
use log::{error, info};

use crate::cert_test::CertTest;

mod cert;
mod cert_test;
mod error;
mod ssl_config;

/// Certo - TLS Certificate impending expiration checker
///
/// By default, uses the Operating System's Root Certificate Store however use
/// of custom certificates overrides this behaviour.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Warn about near expiration if within this number of days of the cert's
    /// notAfter
    #[arg(short = 'd', default_value = "5")]
    days_to_expiration: i64,

    /// Custom root PEM certificates to use for verification.
    /// Can be either a certificate, or a collection of concatenated PEM certs.
    #[arg(short = 'c')]
    custom_ca_certs: Vec<std::path::PathBuf>,

    /// Force use of the system-installed root certificate store if default
    /// behaviour is overriden by use of custom root certificates
    #[arg(short = 'F', long, default_value = "false")]
    force_system_root_store: bool,

    /// Output results in json format for further processing
    #[arg(short = 'j', long, default_value = "false")]
    json: bool,

    /// [List of] Hosts to check the certificates of
    #[arg(required = true)]
    hosts: Vec<String>,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Config: {:#?}", args);

    let mut root_store = rustls::RootCertStore::empty();

    if args.custom_ca_certs.is_empty() {
        ssl_config::load_root_certs(&mut root_store);
    } else {
        ssl_config::load_pem_certs(&mut root_store, args.custom_ca_certs);
        if args.force_system_root_store {
            ssl_config::load_root_certs(&mut root_store);
        }
    }

    let config = Arc::new(ssl_config::safe_clientconfig(root_store));

    let tests: Vec<_> = args
        .hosts
        .iter()
        .map(|hostname| CertTest::new(hostname, args.days_to_expiration, config.clone()))
        .collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&tests).unwrap());
    } else {
        tests.iter().for_each(
            |t| match &t.result {
                Ok(remaining_days) => info!(
                    "[ PASS ] {}: {} days remaining", t.hostname, remaining_days),
                Err(e) => error!("[ FAIL ] {}: {}", t.hostname, e),
            }
        )
    }

    if tests.iter().all(|t| t.result.is_ok()) {
        Ok(())
    } else {
        Err(Error::CertoTestFailure(1))
    }
}
