# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project adheres to [Semantic Versioning](https://semver.org/).

## [v0.6.0-verifier]

> **Interim release — most users should wait for `v0.6.0`.** `v0.6.0-verifier` ships the
> content-negotiation capability (client-selectable identity formats plus the verifier that
> honors them) while keeping every provider's default identity byte-identical to prior
> releases, so it stays fully compatible with the auth server deployed today. It is one step
> in a staged rollout:
> 1. **`v0.6.0-verifier`** (this release) adds negotiation with the historical defaults.
> 2. The auth-service verifier that honors the `X-S2IAM-Identity-Format-Preference` header is
>    deployed (takes a few days).
> 3. **`v0.6.0`** then flips the built-in AWS default to the session-stripped base IAM role
>    ARN (`[aws-iam-role-arn, aws-arn]`).
>
> Unless you need to opt into a non-default identity format now, or you are deploying your own
> verifier, wait for `v0.6.0`.

### Added
- **Client-selectable identity-format preference lists (content negotiation).** Clients
  may now request an ordered list of identity representations; the verifier picks the
  first form it supports and can derive, and reports the chosen form back. This is
  **fully additive and non-breaking**: the default identity for every provider is
  byte-identical to prior releases unless a client opts in.
  - New provider-prefixed format vocabulary: `aws-arn` (raw STS/IAM ARN, current default;
    session-bearing for assumed roles),
    `aws-iam-role-arn` (session-stripped base IAM role ARN), `aws-role-id`
    (stable `RoleId`, `AROA…`), `gcp-sa-email`, `gcp-sa-unique-id`, `azure-object-id`,
    and `azure-resource-id` (`xms_mirid`, user-assigned managed identity).
  - Preference is set via the `WithIdentityFormatPreference(...)` option (Go),
    `identity_format_preference=[...]` (Python), `Options.withIdentityFormatPreference(...)`
    / `.identityFormatPreference(...)` (Java), the `--identity-format-preference` CLI flag,
    or the `S2IAM_IDENTITY_FORMAT_PREFERENCE` environment variable (comma-separated).
    Precedence is explicit option > environment variable > built-in default.
  - The preference travels on the `X-S2IAM-Identity-Format-Preference` request header.
    The verifier's response includes an `identityFormat` field naming the selected form.
  - Negotiation only reorders among representations the verifier has already derived for
    the authenticated identity; an unsupported or inapplicable preference falls back to
    the server default and ultimately to the always-valid floor (`aws-arn`,
    `gcp-sa-unique-id`, `azure-object-id`). It can never broaden a match or cross identities.
  - To adopt the session-stripped base IAM role ARN for AWS, request
    `["aws-iam-role-arn", "aws-arn"]`. The raw STS assumed-role ARN, role session name, and
    STS `UserId` remain available in `AdditionalClaims` / `additional_claims` / identity
    claims for audit regardless of the chosen format.
  - Verifier operators can change the default ordering via
    `VerifierConfig.DefaultIdentityFormats` (Go) — a single flat preference list spanning
    providers (each token names its own provider); the built-in defaults preserve historical
    behavior (`[aws-arn]`, `[gcp-sa-email, gcp-sa-unique-id]`, `[azure-object-id]`).

### Changed
- **Python now requires 3.10 or newer** (was 3.9). Python 3.9 reached end of life in
  October 2025 and is no longer supported by the type checker the project pins.

### Fixed
- Authentication guide and OpenAPI examples use a UUID for `workspaceGroupID`. The auth server rejects non-UUID values such as `wg-...`.

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
