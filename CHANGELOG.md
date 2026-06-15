# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]
### Added
- Optional AWS `RoleSessionName` when assuming a role (Go `WithAssumeRoleSessionName`, Python `assume_role_session_name`, Java `Options.withAssumeRoleSessionName`, CLI `--assume-role-session-name`). Default assume-role behavior is unchanged when the option is omitted.

## [v0.4.0] - 2026-06-12
### Added
- OpenAPI specification for the IAM HTTP API (`docs/api/openapi.yaml`) with authentication guide (`docs/api/AUTHENTICATION.md`), local `make docs-api-lint` / `make docs-api-html` targets, and GitHub Pages deployment workflow.
- Go CSP verifier positive principal format validation (AWS caller identity ARN, Azure UUID, GCP service account email or numeric principal), gated by `S2IAMValidatePrincipal` codegate (enabled by default).
- `--allow-http` CLI flag for local and integration testing against HTTP servers.
- Structured Java detection attempt statuses (`DetectAttemptStatus`) and accompanying test.
- Minimal Java install section in root README.
- Maven Central release workflow for the Java client (`v*` tag push, `-Prelease` profile with GPG signing and Sonatype Central publishing).
- PyPI Trusted Publishing workflow for the Python package (`v*` tag push via GitHub OIDC; no long-lived API token in repository secrets).

### Changed
- Require HTTPS for authentication server URLs by default across Go, Java, and Python; opt in with `WithAllowHTTP()` (Go), `Options.withAllowHttp()` (Java), or `allow_http=True` (Python). Server URL scheme is validated before cloud provider detection.
- Simplified Java concurrent detection error attribution (removed index inference; provider wrapped in exception).
- Removed verbose cloud detection overview from README to keep focus on user API.
- Cloud provider CI tests serialized per VM host via remote locks; hosts defined in `.github/cloud-test-hosts.json` with stale-lock cleanup workflow.

### Fixed
- Python GCP cancellation unraisable warning suppressed.
- Python long line lint issue (E501) in GCP client.

## [v0.3.0] - 2025-10-23
### Added
- Java client library (builder API, assume role / impersonation, audience validation for GCP).
- Two-phase detection + workload identity / IRSA support improvements across languages.
- Makefile for common tasks.

### Changed
- Unified detection timeout to 10s (Java & Python) with structured timing flags.
- Enhanced error surface: Java `NoCloudProviderDetectedException` now carries attempt statuses.

### Fixed
- Setup and CI adjustments (updated actions).

## [v0.2.0] - 2025-08-19
### Added
- Python client library (async convenience functions `get_jwt_database`, `get_jwt_api`).
- Cloud provider detection parity improvements (fast path + concurrent metadata probes).
- GCP test coverage in CI.

### Fixed
- Role handling corrections (Azure no assume role; AWS/GCP email identifier logic).
- Code coverage stability fixes.

## [v0.1.0] - 2025-08-19
### Added
- Initial Go client and CLI (`s2iam`) providing JWT acquisition for database and API access.
- CI pipeline for Go (tests + coverage + lint).

### Changed
- Documentation links and minor fixes prior to Python addition.

## [0.0.1] - 2025-08-?? (Internal bootstrap)
### Added
- Repository initialization, preliminary Go scaffolding.

---

## Release Alignment
Versions are kept in sync across languages (Go, Python, Java). A version tag indicates feature parity for core convenience APIs and detection semantics.

## Tagging & Publishing
- Go: tag `go/vX.Y.Z` triggers module availability on proxy & pkg.go.dev.
- Python: push `vX.Y.Z` tag to run Trusted Publishing workflow to PyPI.
- Java: push `vX.Y.Z` tag to run Maven Central release workflow (OSSRH).

[Unreleased]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.4.0...HEAD
[v0.4.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.3.0...go/v0.4.0
[v0.3.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.2.0...go/v0.3.0
[v0.2.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.1.0...go/v0.2.0
[v0.1.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/0.0.1...go/v0.1.0
