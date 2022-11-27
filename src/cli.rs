use clap::Parser;

/// Certo - TLS Certificate impending expiration checker
///
/// By default, uses the Operating System's Root Certificate Store however use
/// of custom certificates overrides this behaviour.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Warn about near expiration if within this number of days of the cert's
    /// notAfter.
    #[arg(short = 'd', default_value = "5")]
    pub days_to_expiration: i64,

    /// Custom root PEM certificates to use for verification.
    /// Can be either a certificate, or a collection of concatenated PEM certs.
    #[arg(short = 'c')]
    pub custom_ca_certs: Vec<std::path::PathBuf>,

    /// Force use of the system-installed root certificate store if default
    /// behaviour is overriden by use of custom root certificates.
    #[arg(short = 'F', long, default_value = "false")]
    pub force_system_root_store: bool,

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
    #[arg(required = true)]
    pub hosts: Vec<String>,
}
