# Certo, the certificate expiry watchdog

Certo checks a hosts' certificate (at the moment only _via_ HTTP1.1) for impending expiry, and reports its findings in a legible manner (optionally serialised as JSON).

This makes it useful for checking your certificates regularly via cron, CI tools. JSON output enables easy integration into pipelines.

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

## Examples

### Test a working website

```shell
$ RUST_LOG=info certo google.com
[2023-08-22T19:13:12Z INFO  certo] [ PASS ] google.com: 61 days remaining
$ echo $?
0
```

### Certo will error out if maximum days to expiry is too big
```shell
$ certo -d 62 google.com
    Finished dev [unoptimized + debuginfo] target(s) in 0.06s
     Running `target/debug/certo -d 62 google.com`
[2023-08-22T19:29:40Z ERROR certo] [ FAIL ] google.com: Certificate about to expire in 61 days < 62
Error: CertoTestFailure(1)
```

### Test an expired certificate

```shell
$ certo expired.badssl.com
[2023-08-22T19:25:07Z ERROR certo] [ FAIL ] expired.badssl.com: Invalid Certificate: invalid peer certificate: Expired.
Error: CertoTestFailure(1)
```

### Test several websites, output as JSON
**Note:** in this case all checks must pass for overall success

```shell
$ certo -j -d 62 microsoft.com google.com
    Finished dev [unoptimized + debuginfo] target(s) in 0.06s
     Running `target/debug/certo -j -d 62 microsoft.com google.com`
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
    "message": "Certificate about to expire in 61 days < 62",
    "remainingDays": null
  }
]
Error: CertoTestFailure(1)
```

**Note:** setting a custom ca certificate will override the system root store

```shell
$ certo -j -d 62 -c tests/certs/isrgrootx1.pem google.com
[2023-08-22T19:47:23Z INFO  certo::ssl_config] Added 1 and ignored 0 certificates from tests/certs/isrgrootx1.pem
[
  {
    "hostname": "google.com",
    "success": false,
    "message": "Invalid Certificate: invalid peer certificate: UnknownIssuer.",
    "remainingDays": null
  }
]
Error: CertoTestFailure(1)
```

You can override this using --force-system-root-store

```shell
$ certo -j -d 62 -c tests/certs/isrgrootx1.pem --force-system-root-store google.com`
[2023-08-22T19:49:10Z INFO  certo::ssl_config] Added 1 and ignored 0 certificates from tests/certs/isrgrootx1.pem
[
  {
    "hostname": "google.com",
    "success": false,
    "message": "Certificate about to expire in 61 days < 62",
    "remainingDays": null
  }
]
Error: CertoTestFailure(1)
```
