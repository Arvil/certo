# Certo, the certificate expiry watchdog

Certo checks a hosts' certificate (at the moment only _via_ HTTP1.1) for impending expiry, and reports its findings in a legible manner (optionally serialised as JSON).

## Usage

```
Usage: certo [OPTIONS] <HOSTS>...

Arguments:
  <HOSTS>...  [List of] Hosts to check the certificates of

Options:
  -d <DAYS_TO_EXPIRATION>        Warn about near expiration if within this number of days of the cert's notAfter [default: 5]
  -c <CUSTOM_CA_CERTS>           Custom root PEM certificates to use for verification. Can be either a certificate, or a collection of concatenated PEM certs (certificate bundle)
  -F, --force-system-root-store  Force use of the system-installed root certificate store if default behaviour is overriden by use of custom root certificates
  -j, --json                     Output results in json format for further processing
  -h, --help                     Print help information
  -V, --version                  Print version information
```