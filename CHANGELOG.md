# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]
### Added
- Structured Java detection attempt statuses (`DetectAttemptStatus`) and accompanying test.
- Minimal Java install section in root README.

### Changed
- Simplified Java concurrent detection error attribution (removed index inference; provider wrapped in exception).
- Removed verbose cloud detection overview from README to keep focus on user API.

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
- Python: planned GitHub Action to build wheel/sdist and publish to PyPI.
- Java: planned GitHub Action to deploy to Maven Central (OSSRH) once credentials & GPG keys configured.

[Unreleased]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.3.0...HEAD
[v0.3.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.2.0...go/v0.3.0
[v0.2.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.1.0...go/v0.2.0
[v0.1.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/0.0.1...go/v0.1.0