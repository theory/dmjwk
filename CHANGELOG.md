# Changelog

All notable changes to this project will be documented in this file. It uses the
[Keep a Changelog] format, and this project adheres to [Semantic Versioning].

  [Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
  [Semantic Versioning]: https://semver.org/spec/v2.0.0.html
    "Semantic Versioning 2.0.0"

## [v0.2.3] — 2026-03-15

🏗️ Build Setup

*   Enabled all of the `vacuum` rules and integrated its repo into
    `.pre-commit-config.yaml`.

### ⬆️ Dependencies

*   Upgraded to Go 1.26.1
*   Upgraded golangci-lint to v2.11.3 and fixed issues
*   Updated all dependencies

### 📚 Documentation

*   Improved [`openapi.json`](openapi.json) by adding `license` and `contact`
    properties to the `info` object, setting just a single tag for each API,
    and adding a 400 response to the `/openapi.json` and
    `/.well-known/jwks.json` APIs.

  [v0.2.3]: https://github.com/theory/jsonpath/compare/v0.2.2...v0.2.3

## [v0.2.2] — 2026-01-24

⬆️ Dependency Updates

*   Upgraded to latest version of `golang.org/x/time`.

🏗️ Build Setup

*   Added a test for server shutdown timeout.

  [v0.2.2]: https://github.com/theory/jsonpath/compare/v0.2.1...v0.2.2

## [v0.2.1] — 2026-01-13

### 🐞 Bug Fixes

*   Updated the `/authorization` API to reject empty grant type, username, and
    password values.

  [v0.2.1]: https://github.com/theory/jsonpath/compare/v0.2.0...v0.2.1

## [v0.2.0] — 2025-12-30

### ⚡ Improvements

*   Updated the `DMJWK_AUDIENCE` variable to take a comma-delimited list of
    audiences, all of which will be set in the `aud` field of JWTs generated
    by the `/authorization` API
*   Documented that the `aud` parameter to the `/authorization` API may be
    specified multiple times, in which case all of its values will fill the
    `aud` field of JWT it generates
*   Added the contents of the `scope` form field to the `/authorization` API to
    the resulting JWT in accordance with [RFC 8693]
*   Added never-failing Basic Auth to the `/authorization` API that sets the JWT
    `client_id` claim to the username.
*   Added the `client_id` field to the `/authorization` API that sets the JWT
    `client_id` claim unless Basic auth provides it.

### 🏗️ Build Setup

*   Added CI workflows for FreeBSD, OpenBSD, and NetBSD on amd64 and arm64

### 📚 Documentation

*   Added installation instructions to the [README](README.md)
*   Added Docker example to the Quick Start in the [README](README.md)
*   Converted dumb quotes to smart quotes in [openapi.json](openapi.json)

  [v0.1.1]: https://github.com/theory/jsonpath/compare/v0.1.0...v0.2.0
  [RFC 8693]: https://www.rfc-editor.org/rfc/rfc8693#name-json-web-token-claims-and-i
    "RFC 8693 Section 4: JSON Web Token Claims and Introspection Response Parameters"

## [v0.1.0] — 2025-12-28

### ⚡ Improvements

*   First release, everything is new!
*   Generates a JWK set with a configurable number of keys
*   Provides `/.well-known/jwks.json` to fetch the public JWK set
*   Provides `/authorization` to create a JWT via [Resource Owner Password Credentials Grant]
*   Provides `/resource` to validate a JWT via [OAuth 2 Bearer Token]
*   Provides `/openapi.json` to describe the API

### 🏗️ Build Setup

*   Built with Go
*   Makes [releases] for 40 platforms
*   Run [ghrc.io/theory/dmjwk] in Docker
*   Use `go install` to install from pkg.go.dev

### 📚 Documentation

*   Docs in [README.md](README.md)
*   Complete docs in [openapi.json](openapi.json)

  [v0.1.0]: https://github.com/theory/jsonpath/compare/15b3562...v0.1.0
  [Resource Owner Password Credentials Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
  [OAuth 2 Bearer Token]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
    "RFC 6750 --- The OAuth 2.0 Authorization Framework: Bearer Token Usage"
  [releases]: https://github.com/theory/dmjwk/releases "dmjwk Releases"
  [ghrc.io/theory/dmjwk]: https://ghcr.io/theory/dmjwk "dmjwk OCI Images"
