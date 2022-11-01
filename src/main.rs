use std::sync::Arc;

use clap::Parser;
use error::{Error, Result};
use log::info;

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

    /// Custom root certificates to use for verification. Expected to be 
    /// DER-encoded root certificates are expected to be found within.
    #[arg(short = 'c')]
    custom_root_certs: Vec<std::path::PathBuf>,

    /// Force use of the system-installed root certificate store if default 
    /// behaviour is overriden by use of custom root certificates
    #[arg(short = 'F', long, default_value="false")]
    force_system_root_store: bool,

    /// [List of] Hosts to check the certificates of
    #[arg(required = true)]
    hosts: Vec<String>,
}

/// TODO add tests
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Config: {:?}", args);

    let mut root_store = rustls::RootCertStore::empty();
    if !args.custom_root_certs.is_empty() {
        ssl_config::load_certs(&mut root_store, args.custom_root_certs);
        if args.force_system_root_store {
            ssl_config::load_root_certs(&mut root_store);
        }
    } else {
        ssl_config::load_root_certs(&mut root_store);
    }

    let config = Arc::new(ssl_config::safe_clientconfig(root_store));

    let tests: Vec<_> = args
        .hosts
        .iter()
        .map(|hostname| CertTest::new(hostname, args.days_to_expiration, config.clone()))
        .collect();

    println!("{}", serde_json::to_string_pretty(&tests).unwrap());

    if tests.iter().all(|t| t.result.is_ok()) {
        Ok(())
    } else {
        Err(Error::CertoTestFailure(1))
    }
}
