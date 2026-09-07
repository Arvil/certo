// This file is part of the `certo` project.

use std::io;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use rustls::ClientConnection;
use rustls_pki_types::CertificateDer;

use crate::error::{Error, Result};

/// Perform a TLS handshake against `hostname:port` and return the peer
/// certificate chain.
///
/// A minimal HTTP/1.1 `HEAD` request is written once the handshake completes;
/// its response is never read — the certificate chain is obtained from the
/// handshake itself.
pub fn get_peer_cert_chain(
    conn: &mut ClientConnection,
    hostname: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<CertificateDer<'static>>> {
    let mut sock = connect(hostname, port, timeout)?;
    // Keep a stalled server from hanging the handshake forever.
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| io_error(hostname, port, "setting socket timeout", e))?;
    sock.set_write_timeout(Some(timeout))
        .map_err(|e| io_error(hostname, port, "setting socket timeout", e))?;

    let mut tls = rustls::Stream::new(conn, &mut sock);

    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n"
    );
    match tls.write_all(request.as_bytes()) {
        Ok(()) => {}
        Err(e) if is_timeout(&e) => {
            return Err(Error::HandshakeTimeout {
                hostname: hostname.to_string(),
                port,
                seconds: timeout.as_secs(),
            });
        }
        Err(e) => {
            return Err(Error::InvalidCertificate {
                why: format!("TLS handshake failed: {e}"),
            });
        }
    }

    if conn.is_handshaking() {
        return Err(Error::HandshakeTimeout {
            hostname: hostname.to_string(),
            port,
            seconds: timeout.as_secs(),
        });
    }

    let chain = conn.peer_certificates().ok_or(Error::NoCertificate)?;
    Ok(chain.iter().map(|cert| cert.clone().into_owned()).collect())
}

/// Open a TCP connection to `hostname:port`, trying each resolved address in
/// turn until one succeeds.
fn connect(hostname: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addrs: Vec<_> = (hostname, port)
        .to_socket_addrs()
        .map_err(|e| Error::ConnectionFailure {
            hostname: hostname.to_string(),
            port,
            why: format!("name resolution failed: {e}"),
        })?
        .collect();

    if addrs.is_empty() {
        return Err(Error::ConnectionFailure {
            hostname: hostname.to_string(),
            port,
            why: "name resolved to no addresses".to_string(),
        });
    }

    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(sock) => return Ok(sock),
            Err(e) => last_error = Some(e),
        }
    }

    let why = match last_error {
        Some(e) if is_timeout(&e) => {
            format!("timed out after {}s", timeout.as_secs())
        }
        Some(e) => e.to_string(),
        None => "no addresses could be contacted".to_string(),
    };
    Err(Error::ConnectionFailure {
        hostname: hostname.to_string(),
        port,
        why,
    })
}

/// Socket timeouts surface as `WouldBlock` on unix and `TimedOut` elsewhere.
fn is_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn io_error(hostname: &str, port: u16, context: &str, err: io::Error) -> Error {
    Error::ConnectionFailure {
        hostname: hostname.to_string(),
        port,
        why: format!("{context}: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_timeout_kinds() {
        assert!(is_timeout(&io::Error::from(io::ErrorKind::WouldBlock)));
        assert!(is_timeout(&io::Error::from(io::ErrorKind::TimedOut)));
        assert!(!is_timeout(&io::Error::from(io::ErrorKind::Other)));
    }

    #[test]
    fn test_connect_refused() {
        // Bind then drop the listener so the port is (almost certainly) closed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let err = connect("127.0.0.1", port, Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, Error::ConnectionFailure { .. }), "{err:?}");
    }

    #[test]
    fn test_connect_name_resolution_failure() {
        let err = connect("nonexistent-host.invalid", 443, Duration::from_secs(1)).unwrap_err();
        match &err {
            Error::ConnectionFailure { why, .. } => {
                assert!(why.contains("name resolution"), "{why}")
            }
            other => panic!("expected ConnectionFailure, got {other:?}"),
        }
    }
}
