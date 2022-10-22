use std::sync::Arc;
use time::OffsetDateTime;

use error::Error;
use x509_parser::prelude::{X509Certificate, FromDer};

mod config;
mod cert;
mod error;

fn main() -> Result<(), Error> {
    let root_store = config::load_root_certs();
    let config = Arc::new(config::safe_clientconfig(root_store));
    let hostname = "google.com";

    let server_name = hostname.try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(config, server_name).unwrap();

    let chain = cert::get_cert_chain(&mut conn, hostname)?;
    let leaf_der = &chain.first().unwrap().0[..];

    let certificate = {
        if let Ok((_, leaf_cert)) = X509Certificate::from_der(&leaf_der) {
            Some(leaf_cert)
        } else {
            None
        }
    }.unwrap();

    println!("{:#}", &certificate.tbs_certificate.subject);
    println!("{:#}", &certificate.tbs_certificate.validity.not_after);

    let not_after = &certificate.tbs_certificate.validity().not_after.to_datetime();
    let now = OffsetDateTime::now_utc();
    println!("{:#}", (*not_after - now).whole_days());

    Ok(())
}
