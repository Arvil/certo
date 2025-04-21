// This file is part of the `certo` project.

use rustls_pki_types::CertificateDer;

pub struct ClientAuthenticationCredentials<'a> {
    pub cert_chain: Vec<CertificateDer<'a>>,
    pub key_der: rustls_pki_types::PrivateKeyDer<'a>,
}

