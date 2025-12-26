dmjwk
=====

dmjwk (pronounced "dumb jock") is a simple demo web server that provides a
basic [Resource Owner Password Credentials Grant] OAuth 2 flow that returns a
[JSON Web Tokens] for "authenticated" users. It signs the tokens with a
memory-persistent [JSON Web Key] set.

> [!CAUTION]
>
> ## Do Not Use in Production
>
> This is not a serious IDP. It's designed exclusively for use demoing
> applications that depend on an IDP. It stores no data, releases all JSON Web
> Keys on shutdown, and authenticates users in a very silly way.
>
> **You have been warned.**

## Usage

dmjwk takes only a single argument `--version` (or just `version`), which
causes it to print the version information and exit:

```console
dmjwk --version
dmjwk version v0.1.0 (0903349)
```

## Configuration

Otherwise it must be configured through the use of the following environment
variables:

### DMJWK_KEY_PATH and DMJWK_CERT_PATH

Paths relative to `DMJWK_CONFIG_DIR` for the TLS public/private key pairs the
server will use to identify itself. The files must contain PEM encoded data.
The certificate file may contain intermediate certificates following the leaf
certificate to form a certificate chain.

If no `DMJWK_KEY_PATH` is provided, dmjwk will create a self-signed
certificate.

### DMJWK_CONFIG_DIR

Path to the configuration directory. Defaults to `/etc/dmjwk`. If no
`DMJWK_KEY_PATH` is specified, dmjwk will create a self-signed certificate and
write a PEM-formatted CA bundle file named `ca.pem` into this directory. Use
this file to make verified requests to the dmjwk server, for example via the
[curl] `--cacert` option or `CURL_CA_BUNDLE` environment variable.

### DMJWK_HOST_NAMES

Comma-delimited list of host names to include in the self signed certificate
in addition to the IP addresses `127.0.0.1`, `0.0.0.0`, the IPv6 loopback
address, and variants of `localhost`. Not used when `DMJWK_KEY_PATH` and
`DMJWK_CERT_PATH` provide a certificate.

### DMJWK_PORT

The port on which dmjwk will listen. Defaults to `443`.

### DMJWK_KIDS

Comma-delimited list of key identifiers. dmjwk will create a JSON Web Key
(JWK) for each. If none is provided it will create a single key with no KID.
Otherwise, the first ID in the list will identify the default key used to sign
JSON Web Tokens (JWTs) returned  by the `/authorization` endpoint.

### DMJWK_ISSUER

Name to use for the `iss` field of JSON Web Tokens (JWTs) returned by the
`/authorization` endpoint.

### DMJWK_AUDIENCE

Name to use for the `aud` field of JSON Web Tokens (JWTs) returned by the
`/authorization` endpoint.

### DMJWK_EXPIRE_AFTER

Amount of time assigned to the `exp` field of JSON Web Tokens (JWTs) returned
by the `/authorization` endpoint. Specif as a duration string, a possibly
signed sequence of decimal numbers, each with optional fraction and a unit
suffix, such as "300ms", "-1.5h" or "2h45m". Valid time units are "ns", "us"
(or "µs"), "ms", "s", "m", "h". Defaults to "1h".

  [JSON Web Key]: https://www.rfc-editor.org/rfc/rfc7517
    "RFC 7517 JSON Web Key (JWK)"
  [JSON Web Tokens]: https://www.rfc-editor.org/rfc/rfc7519
    "RFC 7519 JSON Web Token (JWT)"
  [Resource Owner Password Credentials Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
  [curl]: https://everything.curl.dev/usingcurl/tls/verify.html#ca-store-in-files
    "everything curl: CA store in file(s)"
