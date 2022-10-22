use std::{net::TcpStream, io::{Write}};
use rustls::{ClientConnection};

use crate::error::Error;

pub fn get_cert_chain<'a>(conn: &'a mut ClientConnection, hostname: &str) -> Result<&'a[rustls::Certificate], Error>  {
    let mut sock = TcpStream::connect(format!("{}:443", hostname)).map_err(|_| Error::ConnectionError)?;
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