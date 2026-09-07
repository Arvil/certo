# Certo, the certificate expiry watchdog

Certo checks a hosts' certificate (at the moment only _via_ HTTP1.1) for impending expiry, and reports its findings in a legible manner (optionally serialised as JSON).

This makes it useful for checking your certificates regularly via cron, CI tools. JSON output enables easy integration into pipelines.

## Usage

```
Usage: certo [OPTIONS] <HOST[:PORT]>...

Arguments:
  <HOST[:PORT]>...  [List of] Hosts to check the certificates of

Options:
  -d, --days <DAYS_TO_EXPIRATION>
          Warn about near expiration if within this number of days of the cert's notAfter [default: 5]
  -t, --timeout <TIMEOUT_SECONDS>
          Give up on name resolution, connection and TLS handshake after this many seconds [default: 10]
  -c, --custom-ca-certs <FILE>
          Custom root PEM certificates to use for verification. Can be either a certificate, or a collection of concatenated PEM certs
  -F, --force-system-root-store
          Force use of the system-installed root certificate store if default behaviour is overriden by use of custom root certificates
  -w, --webpki-roots
          Use the bundled Mozilla root store instead of the system root store. Useful in containers without a system certificate store; combine with -F to add the system store as well
      --client-cert-chain <CLIENT_CERT_CHAIN>
          Client PEM certificate chain for client authentication
      --client-keyfile <CLIENT_KEYFILE>
          Client keyfile, in PKCS8 format
  -j, --json
          Output results in json format for further processing
  -h, --help
          Print help
  -V, --version
          Print version
```

Hosts may carry an explicit port (`example.com:8443`, `[2001:db8::1]:443`); port 443 is used otherwise. Check results are printed by default; `RUST_LOG=debug` adds verbose diagnostics.

Exit codes: `0` when every check passes, `1` when at least one check fails, `2` on usage errors.

## Examples

### Test a working website

```shell
$ certo google.com
[2025-09-07T19:13:12Z INFO  certo] [ PASS ] google.com: 56 days remaining
$ echo $?
0
```

### Certo will error out if maximum days to expiry is too big
```shell
$ certo -d 62 google.com
[2025-09-07T19:29:40Z ERROR certo] [ FAIL ] google.com: Certificate about to expire in 56 days < 62
Error: Some (1) tests failed
```

### Test an expired certificate

```shell
$ certo expired.badssl.com
[2025-09-07T19:25:07Z ERROR certo] [ FAIL ] expired.badssl.com: Invalid Certificate: TLS handshake failed: invalid peer certificate: certificate expired: verification time 1757268307 (UNIX), but certificate is not valid after 1428883199 (359885446 seconds ago).
Error: Some (1) tests failed
```

### Test several websites, output as JSON
**Note:** in this case all checks must pass for overall success

```shell
$ certo -j -d 62 microsoft.com google.com
[
  {
    "hostname": "microsoft.com",
    "success": true,
    "message": "310 days remaining",
    "remainingDays": 310
  },
  {
    "hostname": "google.com",
    "success": false,
    "message": "Certificate about to expire in 56 days < 62",
    "remainingDays": null
  }
]
Error: Some (1) tests failed
```

**Note:** setting a custom ca certificate will override the system root store

```shell
$ certo -j -d 62 -c tests/certs/isrgrootx1.pem google.com
[
  {
    "hostname": "google.com",
    "success": false,
    "message": "Invalid Certificate: TLS handshake failed: invalid peer certificate: UnknownIssuer.",
    "remainingDays": null
  }
]
Error: Some (1) tests failed
```

You can override this using --force-system-root-store

```shell
$ certo -j -d 62 -c tests/certs/isrgrootx1.pem --force-system-root-store google.com
[
  {
    "hostname": "google.com",
    "success": false,
    "message": "Certificate about to expire in 56 days < 62",
    "remainingDays": null
  }
]
Error: Some (1) tests failed
```

Non-standard ports and IPv6 literals are accepted too:

```shell
$ certo smtp.example.com:465 "[2001:db8::1]:443"
```

## Supply chain & SBOM

Certo is built to be comfortable to deploy in critical environments:

* **Release binaries embed a dependency manifest.** Releases are built with
  [`cargo auditable`](https://github.com/rust-secure-code/cargo-auditable), so
  the list of every dependency (with exact versions) is embedded in the
  binary and discovered automatically by scanners such as
  [`syft`](https://github.com/anchore/syft) or `grype`.
* **A CycloneDX 1.5 SBOM** (`certo-<version>.cdx.json`) is attached to every
  GitHub release, alongside SHA256 checksums of all artifacts.
* **CI gates**: every commit is checked with `cargo fmt`, `clippy -D
  warnings`, the test suite and a RustSec advisory audit
  (`cargo audit`); a CycloneDX SBOM is generated as a build artifact.
* **Dependencies are reviewed automatically**: Dependabot watches both the
  Cargo and GitHub Actions ecosystems weekly.
* The MSRV (minimum supported Rust version) is declared in `Cargo.toml`
  (`rust-version = 1.88`) and the release binary is stripped and
  LTO-optimised.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities and generating
SBOMs locally.

## Development

The minimum supported Rust version is 1.88.

```shell
cargo build                 # build
cargo test                  # unit + end-to-end tests (no network required)
cargo clippy --all-targets  # lint
cargo fmt --check           # formatting
cargo audit                 # RustSec advisories (cargo install cargo-audit)
cargo cyclonedx -f json     # SBOM (cargo install cargo-cyclonedx)
```

The end-to-end tests (`tests/end_to_end.rs`) run a real TLS server in-process
on an ephemeral port using throwaway certificates generated with `rcgen`, so
they exercise verification, expiry and failure paths deterministically
without network access.
