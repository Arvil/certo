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
* TLS cryptography uses the `ring` provider via rustls (chosen for minimal
  build dependencies; see the CHANGELOG for the trade-off and the
  FIPS-oriented alternative).
* Release binaries are built with LTO and stripped (`[profile.release]`).

## CI hardening

The workflows in `.github/workflows/` follow GitHub's security hardening
practices for the automatic `GITHUB_TOKEN`:

* **Least privilege** — the token is read-only (`contents: read`) for every
  job; only the release jobs that create or upload to GitHub Releases get
  `contents: write`.
* **Read-only repository default** — the repository's *Workflow permissions*
  setting is also set to "Read repository contents and packages permissions",
  so even a workflow that forgets to declare a `permissions:` block gets a
  read-only token.  Explicit blocks in the workflows override this default;
  a new workflow that needs write access must declare it.
* **No persisted credentials** — checkouts use `persist-credentials: false`,
  so the token is not stored in the runner's git configuration where
  build scripts or test code could read it.
* **Pinned actions** — every action is pinned to an immutable commit SHA
  (with the version in a comment) instead of a mutable tag, and Dependabot
  keeps those pins updated.
* **No `pull_request_target`** — pull request jobs run with a read-only
  token only, so contributor code executed during `cargo test` cannot
  modify the repository or its settings.
* The repository does not use custom CI secrets; the only credential
  involved is the workflow-scoped `GITHUB_TOKEN` GitHub injects per run.
