use std::sync::Arc;

use clap::Parser;
use error::{Error, Result};
use log::info;

use crate::cert_test::CertTest;

mod cert;
mod cert_test;
mod error;
mod ssl_config;

/// Certo - TLS Certificate Checker
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Warn about near expiration if within this number of days of the cert's notAfter
    #[arg(short = 'd', default_value = "5")]
    days_to_expiration: i64,

    /// [List of] Hosts to check the certificates of
    #[arg(required = true)]
    hosts: Vec<String>,
}

/// TODO add tests
fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::init();

    info!("Config: {:?}", args);

    let root_store = ssl_config::load_root_certs();
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
