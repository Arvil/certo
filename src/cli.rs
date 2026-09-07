// This file is part of the `certo` project.

use clap::Parser;

use crate::error::{Error, Result};

/// The port used when a host is given without an explicit `:port` suffix.
pub const DEFAULT_TLS_PORT: u16 = 443;

/// Split a `host[:port]` target into its hostname and port parts.
///
/// Accepted forms: `example.com`, `example.com:8443`, `127.0.0.1:8443`,
/// `[2001:db8::1]:8443` and bare IPv6 addresses (`2001:db8::1`).  A bracketed
/// IPv6 literal is returned without brackets.
pub fn split_host_port(spec: &str, default_port: u16) -> Result<(String, u16)> {
    let invalid = || Error::InvalidHostname {
        hostname: spec.to_string(),
        why: "expected host[:port], e.g. example.com or example.com:8443".to_string(),
    };

    let spec = spec.trim();
    if spec.is_empty() {
        return Err(invalid());
    }

    if let Some(rest) = spec.strip_prefix('[') {
        // Bracketed IPv6 literal, optionally followed by `:port`.
        let (host, after) = rest.split_once(']').ok_or_else(invalid)?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid());
        }
        let port = match after.strip_prefix(':') {
            Some(port) => port.parse::<u16>().map_err(|_| invalid())?,
            None if after.is_empty() => default_port,
            None => return Err(invalid()),
        };
        Ok((host.to_owned(), port))
    } else if let Some((host, port)) = spec.split_once(':') {
        if port.contains(':') {
            // Multiple colons without brackets: a bare IPv6 address.
            spec.parse::<std::net::Ipv6Addr>().map_err(|_| invalid())?;
            Ok((spec.to_owned(), default_port))
        } else if host.is_empty() {
            Err(invalid())
        } else {
            let port = port.parse::<u16>().map_err(|_| invalid())?;
            Ok((host.to_owned(), port))
        }
    } else {
        Ok((spec.to_owned(), default_port))
    }
}

/// Certo - TLS Certificate impending expiration checker
///
/// By default, uses the Operating System's Root Certificate Store however use
/// of custom certificates overrides this behaviour.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Warn about near expiration if within this number of days of the cert's
    /// notAfter.
    #[arg(
        short = 'd',
        long = "days",
        default_value = "5",
        value_parser = clap::value_parser!(i64).range(0..)
    )]
    pub days_to_expiration: i64,

    /// Give up on name resolution, connection and TLS handshake after this
    /// many seconds.
    #[arg(
        short = 't',
        long = "timeout",
        default_value = "10",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub timeout_seconds: u64,

    /// Custom root PEM certificates to use for verification.
    /// Can be either a certificate, or a collection of concatenated PEM certs.
    #[arg(short = 'c', long = "custom-ca-certs", value_name = "FILE")]
    pub custom_ca_certs: Vec<std::path::PathBuf>,

    /// Force use of the system-installed root certificate store if default
    /// behaviour is overriden by use of custom root certificates.
    #[arg(short = 'F', long, default_value_t)]
    pub force_system_root_store: bool,

    /// Use the bundled Mozilla root store instead of the system root store.
    /// Useful in containers without a system certificate store; combine with
    /// -F to add the system store as well.
    #[arg(short = 'w', long, default_value_t)]
    pub webpki_roots: bool,

    /// Client PEM certificate chain for client authentication.
    #[arg(long)]
    pub client_cert_chain: Vec<std::path::PathBuf>,

    /// Client keyfile, in PKCS8 format.
    #[arg(long)]
    pub client_keyfile: Option<std::path::PathBuf>,

    /// Output results in json format for further processing.
    #[arg(short = 'j', long, default_value = "false")]
    pub json: bool,

    /// [List of] Hosts to check the certificates of.
    #[arg(required = true, value_name = "HOST[:PORT]")]
    pub hosts: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_host_port_plain_host() {
        assert_eq!(
            split_host_port("example.com", DEFAULT_TLS_PORT).unwrap(),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn test_split_host_port_with_port() {
        assert_eq!(
            split_host_port("example.com:8443", DEFAULT_TLS_PORT).unwrap(),
            ("example.com".to_string(), 8443)
        );
    }

    #[test]
    fn test_split_host_port_ipv4() {
        assert_eq!(
            split_host_port("127.0.0.1:636", DEFAULT_TLS_PORT).unwrap(),
            ("127.0.0.1".to_string(), 636)
        );
    }

    #[test]
    fn test_split_host_port_bracketed_ipv6() {
        assert_eq!(
            split_host_port("[2001:db8::1]:8443", DEFAULT_TLS_PORT).unwrap(),
            ("2001:db8::1".to_string(), 8443)
        );
        assert_eq!(
            split_host_port("[::1]", DEFAULT_TLS_PORT).unwrap(),
            ("::1".to_string(), 443)
        );
    }

    #[test]
    fn test_split_host_port_bare_ipv6() {
        assert_eq!(
            split_host_port("2001:db8::1", DEFAULT_TLS_PORT).unwrap(),
            ("2001:db8::1".to_string(), 443)
        );
        assert_eq!(
            split_host_port("::1", DEFAULT_TLS_PORT).unwrap(),
            ("::1".to_string(), 443)
        );
    }

    #[test]
    fn test_split_host_port_whitespace_is_trimmed() {
        assert_eq!(
            split_host_port("  example.com  ", DEFAULT_TLS_PORT).unwrap(),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn test_split_host_port_invalid() {
        for spec in [
            "",
            "   ",
            ":",
            "example.com:",
            "example.com:99999",
            "example.com:-1",
            "[::1",
            "[hostname]:443",
            "[::1]:",
            "a:b:8443",
        ] {
            assert!(
                split_host_port(spec, DEFAULT_TLS_PORT).is_err(),
                "expected {spec:?} to be rejected"
            );
        }
    }
}
