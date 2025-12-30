dmjwk
=====

dmjwk (pronounced "dumb jock") is a simple demo web server that provides a
basic [Resource Owner Password Credentials Grant] OAuth 2 flow that returns a
[JSON Web Tokens] for "authenticated" users, as well as a [OAuth 2 Bearer
 Token] API that validates those JWTs. It signs the tokens with a
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

## Installation

### Source

Use [Go] to compile and install from source:

```sh
go install github.com/theory/dmjwk@latest
```

### Docker

Fetch the Docker image to run it locally:

```sh
docker pull ghcr.io/theory/dmjwk
```

### Ubi

Install the [universal binary installer (ubi)][ubi] and use it to install
`dmjwk` and many other tools:

```sh
ubi --project theory/dmjwk --in ~/bin
```

## Quick Start

Start dmjwk with a self-signed certificate:

```sh
env DMJWK_CONFIG_DIR="$(pwd)" DMJWK_PORT=4433 dmjwk
```

Or in Docker:

```sh
docker run -d -p 4433:443 --name dmjwk --volume .:/etc/dmjwk ghcr.io/theory/dmjwk
```

Either command should create `ca.pem` in the current directory. Use it with
your favorite HTTP client to make validated requests. For example, to fetch
the JWK set:

```sh
curl --cacert ca.pem https://localhost:4433/.well-known/jwks.json
```

To fetch a JWT signed by the first key in the JWK set, make an
`application/x-www-form-urlencoded` POST with the required `grant_type`,
`username`, and `password` fields:

```sh
form='grant_type=password&username=kamala&password=a2FtYWxh'
curl --cacert ca.pem -d "$form" https://localhost:4433/authorization
```

Use the `access_token` field in the returned JSON as a Bearer token to reflect
a request to `/resource`:

```sh
tok=$(curl -s --cacert ca.pem -d "$form" https://localhost:4433/authorization | jq -r .access_token)
curl --cacert ca.pem -H "Authorization: Bearer $tok" https://localhost:4433/resource -d '
HELLO WORLD
'
```

Or use the Bearer token for any request to a service that uses
`https://localhost:4433/.well-known/jwks.json` to authenticate requests.

## APIs

See [openapi.json](openapi.json) for the complete documentation. Here's a
summary.

### `GET /openapi.json`

```sh
curl --cacert ca.pem https://localhost:4433/openapi.json
```

Returns [openapi.json](openapi.json). Requires no authentication.

### `GET /.well-known/jwks.json`

```sh
curl --cacert ca.pem https://localhost:4433/.well-known/jwks.json
```

Returns the [JSON Web Key] set generated when the service started. Example
response:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "Ld98DHMIIanlpdOhYf-8GljNHnxHW_i6Bq0iltw9J98",
      "y": "xxyRGhCFIjdQFD-TAs-y6uf18wsPvkq8wH_FsGY1GyU"
    }
  ]
}
```

### `POST /authorization`

```sh
form='grant_type=password&username=kamala&password=a2FtYWxh'
curl --cacert ca.pem -d "$form" https://localhost:4433/authorization
```

[Resource Owner Password Credentials Grant] API. Validates password
authorization for a given username and returns an OAuth 2.0 [Access Token].
Example successful response:

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6IiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJrYW1hbGEiLCJleHAiOjE3NjY5NDQyNzcsImlhdCI6MTc2Njk0MDY3NywianRpIjoiZ3hhNnNib292aTg5dSJ9.04efdORHDA3GIPMnWErMPy4mXXsBfbnMJlzqZsxGVEc2cRvEWI0Mt_IqHDK4RYK_14BCEu2nTMiEPtgwC2IZ5A",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read"
}
```

Returns an `application/json` response with http code 400 on authorization
failure:

```sh
curl --cacert ca.pem -sd "username=hi" https://localhost:4433/authorization
```
```json
{
  "error": "invalid_request",
  "error_description": "missing grant_type"
}
```

### Form fields

**`grant_type`**: Type of grant. Must be "password". Required.

**`username`**: Username to authorize. May be any string. Will be returned in
the JWT `sub` field. Required.

**`password`**: Password. Authentication succeeds base64-encoded username
without trailing equal signs. Required.

**`kid`**: The ID of the Key to use to sign the JWT. Must be one of the values
specified by [DMJWK_KIDS](#dmjwk_kids). Optional.

**`scope`**: Value to include in the `scope` field of the response. Optional.

**`iss`**: Value to include in the the JWT `iss` field. Overrides the value
specified by [DMJWK_ISSUER](#dmjwk_issuer). Optional.

**`aud`**: Value to include in the the JWT `aud` field. Overrides the value
specified by [DMJWK_AUDIENCE](#dmjwk_audience). Optional.

### `POST /resource`

```sh
form='grant_type=password&username=kamala&password=a2FtYWxh'
tok=$(curl -s --cacert ca.pem -d "$form" https://localhost:4433/authorization | jq -r .access_token)
curl --cacert ca.pem -H "Authorization: Bearer $tok" https://localhost:4433/resource -d '
HELLO WORLD
'
```
```text

HELLO WORLD
```

Simple [OAuth 2 Bearer Token] resource API. Submit a JWT returned by
[/authorization](#post-authorization) as a Bearer token and the API will
reflect back the content type and body of the request. If the request contains
no content-type, the returned type will be `application/octet-stream`.

Returns an `application/json` response with http code 401 and an
`WWW-Authenticate` header on authentication failure:

```sh
curl --cacert ca.pem -H "Authorization: Bearer NONE" https://localhost:4433/resource -d 'Hi'
```
```json
{
  "error": "invalid_token",
  "error_description": "token is malformed: token contains an invalid number of segments"
}
```

If dmjwk starts with [DMJWK_ISSUER](#dmjwk_issuer) and/or
[DMJWK_AUDIENCE](#dmjwk_audience) configured, validation will require tokens
contain these values. These values will be set in
[authorization](#post-authorization)-JWTs unless overridden by the `iss`
and/or `aud` form parameters.

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
  [Go]: https://go.dev "The Go Programming Language"
  [ubi]: https://github.com/houseabsolute/ubi
  [Resource Owner Password Credentials Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
  [curl]: https://everything.curl.dev/usingcurl/tls/verify.html#ca-store-in-files
    "everything curl: CA store in file(s)"
  [Access Token]: https://datatracker.ietf.org/doc/html/rfc6749#section-5
    "RFC 6749 Section 5: Issuing an Access Token"
  [OAuth 2 Bearer Token]: https://datatracker.ietf.org/doc/html/rfc6750
    "RFC 6750 --- The OAuth 2.0 Authorization Framework: Bearer Token Usage"
