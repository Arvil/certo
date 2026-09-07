// This file is part of the `certo` project.

//! Certo - TLS certificate impending expiration checker.
//!
//! Library surface for the `certo` binary: connection handling
//! ([`cert`]), certificate evaluation ([`cert_test`]), CLI definition
//! ([`cli`]) and TLS configuration ([`ssl_config`]).

pub mod cert;
pub mod cert_test;
pub mod cli;
pub mod client_auth;
pub mod error;
pub mod ssl_config;
pub mod types;
