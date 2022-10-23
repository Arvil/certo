use rustls::ClientConnection;
use std::{io::Write, net::TcpStream};

use crate::error::{Error, Result};

pub fn get_cert_chain<'a>(
    conn: &'a mut ClientConnection,
    hostname: &str,
) -> Result<&'a [rustls::Certificate]> {
    let mut sock = TcpStream::connect((hostname, 443)).map_err(|_| Error::ConnectionError)?;
    let mut tls = rustls::Stream::new(conn, &mut sock);

    match tls.write_all(
        format!(
            "HEAD / HTTP/1.1\r\nHostname: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
            hostname
        ).as_bytes()
    ) {
        Ok(_) => conn.peer_certificates().ok_or(Error::NoCertificateError),
        Err(e) => Err(Error::InvalidCertificateError{why:format!("{:#}", e)}),
    }
}
