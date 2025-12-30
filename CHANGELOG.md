# Changelog

All notable changes to this project will be documented in this file. It uses the
[Keep a Changelog] format, and this project adheres to [Semantic Versioning].

  [Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
  [Semantic Versioning]: https://semver.org/spec/v2.0.0.html
    "Semantic Versioning 2.0.0"

## [v0.1.1] — Unreleased

### ⚡ Improvements

*   Updated the `DMJWK_AUDIENCE` variable to take a comma-delimited list of
    audiences, all of which will be set in the `aud` field of JWTs generated
    by the `/authorization` API.
*   Documented that the `aud` parameter to the `/authorization` API may be
    specified multiple times, in which case all of its values will fill the
    `aud` field of JWT it generates.

### 🏗️ Build Setup

*   Added CI workflows for FreeBSD, OpenBSD, and NetBSD on amd64 and arm64

### 📚 Documentation

*   Added installation instructions to the [README](README.md)
*   Added Docker example to the Quick Start in the [README](README.md)

  [v0.1.1]: https://github.com/theory/jsonpath/compare/v0.1.0...v0.1.1

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
