use rustls::ClientConnection;
use rustls_pki_types::CertificateDer;
use std::{io::Write, net::TcpStream};
use log::error;

use crate::error::{Error, Result};

pub fn get_cert_chain<'a>(
    conn: &'a mut ClientConnection,
    hostname: &str,
) -> Result<&'a [CertificateDer<'a>]> {
    let mut sock = TcpStream::connect((hostname, 443))
        .map_err(|e| Error::ConnectionFailure {
            hostname: hostname.to_string(),
            details: format!("{}", e)
        })?;
    let mut tls = rustls::Stream::new(conn, &mut sock);

    match tls.write_all(
        // TODO support non-http1.1
        format!(
            "HEAD / HTTP/1.1\r\nHostname: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
            hostname
        ).as_bytes()
    ) {
        Ok(_) => conn.peer_certificates()
            .ok_or(Error::NoCertificate),
        Err(e) => {
            error!("Failed to write to TLS stream for host {}: {}", hostname, e);
            Err(Error::InvalidCertificate{why:format!("Failed to establish TLS connection: {}", e)})
        },
    }
}
