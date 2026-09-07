# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-07

### Fixed

- `certo` no longer panics (exit 101) on malformed input: invalid hostnames,
  `host:port` targets and unparsable peer certificates are reported as
  regular per-host failures with exit code 1.
- Fixed inverted error logging when loading custom CA certificates: adding a
  certificate successfully logged "Failed to read certificate from …".
- A custom CA file that cannot be opened, or that contains no certificates,
  is now a hard error instead of being silently ignored.
- Client authentication arguments are validated pairwise: supplying
  `--client-keyfile` without `--client-cert-chain` (or vice versa) errors
  out instead of silently disabling client authentication.
- Unreadable client certificate chain files are no longer silently dropped.
- The HTTP request sent after the handshake uses a correct `Host` header
  (was `Hostname:`).
- Already-expired server certificates keep failing the handshake with
  rustls' precise verification message.

### Added

- `host:port` targets, including IPv4, IPv6 literals and bracketed IPv6
  (`example.com:8443`, `[2001:db8::1]:443`); the default port remains 443.
- `--timeout <SECONDS>` (`-t`) bounding name resolution, TCP connect and the
  TLS handshake, so a stalled server cannot hang CI.
- `--webpki-roots` (`-w`) to verify against the bundled Mozilla root store —
  useful in containers without a system certificate store.
- `--days` as the long form of `-d`, with input validation (negative values
  rejected at the CLI).
- PASS/FAIL lines are printed by default; `RUST_LOG` still controls the
  level for quieter output.
- Supply-chain support: release binaries embed a dependency manifest via
  cargo-auditable, releases ship a CycloneDX 1.5 SBOM and SHA256 checksums,
  and CI generates an SBOM artifact on every build (see SECURITY.md).
- End-to-end test suite running an in-process TLS server with rcgen-generated
  certificates; no network access required.  The crate is now a lib + bin
  split to make this possible.
- CI gates: `cargo fmt --check`, `clippy -D warnings`, RustSec advisory
  audit, SBOM generation; release artifacts are attached to GitHub releases.

### Changed

- TLS crypto provider switched from aws-lc-rs to ring: builds no longer
  require cmake/Perl/NASM, shrinking the dependency tree by nine crates.
  Post-quantum hybrid key exchange (aws-lc-rs-only) is dropped; environments
  requiring FIPS-validated primitives can build with the `aws_lc_rs`
  feature instead.
- Declared MSRV: 1.88 (`rust-version` in `Cargo.toml`).
- Dependency floors raised to currently tested versions; unmaintained
  `rustls-pemfile` replaced by the `rustls-pki-types` PEM API
  (RUSTSEC-2025-0134).
- Dependabot now also covers the GitHub Actions ecosystem and groups
  minor/patch updates.
- Release binaries are stripped and built with LTO.

## [0.1.6] and earlier

See the [GitHub releases](https://github.com/Arvil/certo/releases) for the
history of earlier versions.
