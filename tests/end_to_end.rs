// This file is part of the `certo` project.

//! End-to-end tests: an in-process rustls TLS server driven by throwaway
//! certificates generated with `rcgen`.  No network access is required.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertificateParams, Issuer, KeyPair, SanType};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use time::OffsetDateTime;

use certo::cert_test::CertTest;
use certo::cli::DEFAULT_TLS_PORT;
use certo::error::Error;
use certo::ssl_config;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// A CA and a helper to mint leaves signed by it.
struct TestCa {
    ca_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl TestCa {
    fn new() -> TestCa {
        Self::named("Certo Test CA")
    }

    fn named(subject: &str) -> TestCa {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![subject.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.not_before = OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + time::Duration::days(3650);

        let ca_pem = {
            // A throwaway self-signed certificate just to obtain the PEM.
            params.self_signed(&key).unwrap().pem()
        };
        let issuer = Issuer::new(params, key);
        TestCa { ca_pem, issuer }
    }

    /// A leaf valid from yesterday until `not_after`, valid for 127.0.0.1.
    fn leaf(&self, not_after: OffsetDateTime) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        params.not_before = OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = not_after;
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }
}

/// Serve exactly one TLS connection: complete the handshake, answer the
/// request with an empty 200 and close.
fn serve_one(listener: TcpListener, config: Arc<ServerConfig>) {
    let (sock, _) = listener.accept().expect("accept");
    let _ = sock.set_read_timeout(Some(TEST_TIMEOUT));
    let _ = sock.set_write_timeout(Some(TEST_TIMEOUT));

    let conn = rustls::ServerConnection::new(config).expect("server connection");
    let mut tls = rustls::StreamOwned::new(conn, sock);

    let mut buf = [0u8; 4096];
    let _ = tls.read(&mut buf); // completes the handshake, consumes the request
    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = tls.flush();
    tls.conn.send_close_notify();
    let _ = tls.conn.write_tls(&mut tls.sock);
}

/// Bind an ephemeral port and spawn `serve_one` on it.
fn spawn_server(config: Arc<ServerConfig>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || serve_one(listener, config));
    port
}

fn server_config(cert_pem: &str, key_pem: &str) -> Arc<ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    )
}

/// A client configuration that trusts exactly `ca_pem`.
fn client_config(ca_pem: &str) -> Arc<rustls::ClientConfig> {
    let mut store = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        store.add(cert.unwrap()).unwrap();
    }
    Arc::new(ssl_config::safe_clientconfig(store, None).unwrap())
}

#[test]
fn happy_path_reports_days_remaining() {
    let ca = TestCa::new();
    let not_after = OffsetDateTime::now_utc() + time::Duration::days(90);
    let (leaf_pem, leaf_key_pem) = ca.leaf(not_after);

    let port = spawn_server(server_config(&leaf_pem, &leaf_key_pem));
    let spec = format!("127.0.0.1:{port}");

    let test = CertTest::new(
        &spec,
        DEFAULT_TLS_PORT,
        30,
        client_config(&ca.ca_pem),
        TEST_TIMEOUT,
    );
    assert_eq!(test.hostname, spec);

    // 90 days minus the sub-second remainder truncates to 89 whole days.
    match test.result {
        Ok(days) => assert_eq!(days.0, 89, "expected ~89 whole days, got {}", days.0),
        Err(e) => panic!("expected success, got: {e}"),
    }
}

#[test]
fn untrusted_ca_is_rejected() {
    let ca = TestCa::new();
    // A different subject DN than the serving CA, so chain building fails
    // outright (UnknownIssuer) rather than via a signature mismatch.
    let other_ca = TestCa::named("Certo Other CA");
    let (leaf_pem, leaf_key_pem) = ca.leaf(OffsetDateTime::now_utc() + time::Duration::days(90));

    let port = spawn_server(server_config(&leaf_pem, &leaf_key_pem));

    let spec = format!("127.0.0.1:{port}");
    let test = CertTest::new(
        &spec,
        DEFAULT_TLS_PORT,
        30,
        client_config(&other_ca.ca_pem),
        TEST_TIMEOUT,
    );
    match &test.result {
        Err(Error::InvalidCertificate { why }) => {
            // webpki reports either UnknownIssuer (no anchor matches) or
            // BadSignature (it attempted the single decoy anchor); both mean
            // the certificate was not trusted.
            assert!(
                why.contains("invalid peer certificate"),
                "unexpected message: {why}"
            );
        }
        other => panic!("expected InvalidCertificate, got {other:?}"),
    }
}

#[test]
fn expired_certificate_is_rejected() {
    let ca = TestCa::new();
    let (leaf_pem, leaf_key_pem) = ca.leaf(OffsetDateTime::now_utc() - time::Duration::days(1));

    let port = spawn_server(server_config(&leaf_pem, &leaf_key_pem));

    let spec = format!("127.0.0.1:{port}");
    let test = CertTest::new(
        &spec,
        DEFAULT_TLS_PORT,
        30,
        client_config(&ca.ca_pem),
        TEST_TIMEOUT,
    );
    match &test.result {
        Err(Error::InvalidCertificate { why }) => {
            assert!(
                why.contains("invalid peer certificate"),
                "unexpected message: {why}"
            );
            assert!(
                why.to_lowercase().contains("expire"),
                "unexpected message: {why}"
            );
        }
        other => panic!("expected InvalidCertificate, got {other:?}"),
    }
}

#[test]
fn not_yet_valid_certificate_is_rejected() {
    let ca = TestCa::new();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
    params.not_before = OffsetDateTime::now_utc() + time::Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + time::Duration::days(90);
    let (leaf_pem, leaf_key_pem) = (
        params.signed_by(&key, &ca.issuer).unwrap().pem(),
        key.serialize_pem(),
    );

    let port = spawn_server(server_config(&leaf_pem, &leaf_key_pem));

    let spec = format!("127.0.0.1:{port}");
    let test = CertTest::new(
        &spec,
        DEFAULT_TLS_PORT,
        30,
        client_config(&ca.ca_pem),
        TEST_TIMEOUT,
    );
    match &test.result {
        Err(Error::InvalidCertificate { why }) => {
            assert!(
                why.contains("invalid peer certificate"),
                "unexpected message: {why}"
            );
        }
        other => panic!("expected InvalidCertificate, got {other:?}"),
    }
}

#[test]
fn connection_refused_is_reported() {
    // Bind, learn the port, then drop the listener: nothing is listening.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let ca = TestCa::new();
    let spec = format!("127.0.0.1:{port}");
    let test = CertTest::new(
        &spec,
        DEFAULT_TLS_PORT,
        30,
        client_config(&ca.ca_pem),
        TEST_TIMEOUT,
    );
    match &test.result {
        Err(Error::ConnectionFailure { .. }) => {}
        other => panic!("expected ConnectionFailure, got {other:?}"),
    }
}

#[test]
fn stalled_handshake_times_out() {
    // A server that accepts but never speaks: the client must give up.
    let stall = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = stall.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((sock, _)) = stall.accept() {
            std::thread::sleep(Duration::from_secs(5));
            drop(sock);
        }
    });

    let ca = TestCa::new();
    let spec = format!("127.0.0.1:{port}");
    let test = CertTest::new(
        &spec,
        DEFAULT_TLS_PORT,
        30,
        client_config(&ca.ca_pem),
        Duration::from_secs(1),
    );
    match &test.result {
        Err(Error::HandshakeTimeout { seconds, .. }) => assert_eq!(*seconds, 1),
        other => panic!("expected HandshakeTimeout, got {other:?}"),
    }
}

#[test]
fn invalid_specs_never_panic() {
    let ca = TestCa::new();
    let config = client_config(&ca.ca_pem);

    for spec in ["not a host", "host:", "[::1", "example.com:99999", ""] {
        let test = CertTest::new(spec, DEFAULT_TLS_PORT, 30, config.clone(), TEST_TIMEOUT);
        assert!(
            matches!(test.result, Err(Error::InvalidHostname { .. })),
            "expected InvalidHostname for {spec:?}, got {:?}",
            test.result
        );
    }
}

#[test]
fn ipv6_loopback_target_works() {
    // Skip gracefully on hosts without IPv6.
    let listener = match TcpListener::bind("[::1]:0") {
        Ok(listener) => listener,
        Err(_) => return,
    };
    let port = listener.local_addr().unwrap().port();

    let ca = TestCa::new();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V6(
        std::net::Ipv6Addr::LOCALHOST,
    ))];
    params.not_before = OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + time::Duration::days(90);
    let (leaf_pem, leaf_key_pem) = (
        params.signed_by(&key, &ca.issuer).unwrap().pem(),
        key.serialize_pem(),
    );

    let config = server_config(&leaf_pem, &leaf_key_pem);
    std::thread::spawn(move || serve_one(listener, config));

    let spec = format!("[::1]:{port}");
    let test = CertTest::new(
        &spec,
        DEFAULT_TLS_PORT,
        30,
        client_config(&ca.ca_pem),
        TEST_TIMEOUT,
    );
    // The hostname is reported exactly as the user typed it.
    assert_eq!(test.hostname, format!("[::1]:{port}"));
    assert!(
        test.result.is_ok(),
        "expected success, got {:?}",
        test.result
    );
}
