# Security Policy

Certo is a small tool that is meant to be comfortable to run in critical
environments: CI pipelines, cron jobs, monitoring boxes.  This document
explains how vulnerabilities are handled and how to audit what you run.

## Reporting a vulnerability

Please use GitHub's private security advisories
(**Security → Advisories → New draft security advisory** on the repository)
rather than a public issue.

You can expect an initial response within a week.

## Supported versions

Only the latest published release is supported with security fixes.

## Auditing what you run

### SBOM

Every release ships a CycloneDX 1.5 SBOM (`certo-<version>.cdx.json`) as a
release artifact, listing the complete dependency tree with exact versions.

A dependency manifest is also **embedded in the release binary itself**
(built with [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable)),
so an SBOM can be produced from the artifact you actually downloaded:

```shell
syft ./certo                      # any syft/grype-compatible scanner
```

To generate an SBOM from source instead:

```shell
cargo install cargo-cyclonedx
cargo cyclonedx -f json --spec-version 1.5   # writes certo.cdx.json
```

### Checksums

All release artifacts come with a `SHA256SUMS` file; verify before deploying:

```shell
sha256sum --check SHA256SUMS
```

### Vulnerability scanning

* CI runs a RustSec advisory audit on every commit (`cargo audit` via
  `rustsec/audit-check`).
* Scanning a release binary directly is supported because of the embedded
  manifest: `grype ./certo` or `syft ./certo | grype -`.
* To scan locally from source: `cargo audit`.

## Dependency management

* Dependabot updates Cargo dependencies and GitHub Actions weekly; minor and
  patch updates are grouped to keep pull requests reviewable.
* The minimum supported Rust version (MSRV) is declared as
  `rust-version = 1.88` in `Cargo.toml`.
* Release binaries are built with LTO and stripped (`[profile.release]`).
