# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project adheres to [Semantic Versioning](https://semver.org/).

## [v0.6.0]

> **⚠️ BREAKING CHANGE — the AWS identity your workloads authenticate as changes.**
> Step 3 of 3 of the identity-format rollout begun in `v0.6.0-verifier`. The verifier that
> honors `X-S2IAM-Identity-Format-Preference` is now deployed to the auth service, so the
> clients flip their built-in AWS default to the session-stripped base IAM role ARN.
> **Read [Breaking changes](#breaking-changes) before upgrading an AWS workload**, or skip
> to [Retaining the previous behavior](#retaining-the-previous-behavior).
>
> This release requires a server that honors the preference header; a server that ignores
> it returns the raw caller ARN regardless, so an upgraded client keeps working but does
> not get the new identity.

### Breaking changes
- **The AWS identity requested by default is now the base IAM role ARN.** The Go, Python,
  and Java clients and the `s2iam` CLI lead their preference with `aws-iam-role-arn`
  instead of `aws-arn`, so a workload running under an AWS STS assumed-role session —
  EC2 instance profile, EKS IRSA, or an explicit `AssumeRole` — authenticates as
  `arn:aws:iam::ACCOUNT:role/ROLE` rather than
  `arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION`. The base role ARN is independent of
  the caller-chosen session name, which is what makes it pre-configurable for an EC2
  instance profile (whose session name is the instance id).

  **The JWT `sub` changes, and authentication fails if the new `sub` is not registered.**
  Before upgrading, register `arn:aws:iam::ACCOUNT:role/ROLE` as a cloud principal and
  create matching database users. Both forms can be registered at once, so you can prepare
  ahead of the upgrade and roll back without a gap. `s2iam --print-sub` shows the `sub` you
  will be authorized as. See
  [Identity format preferences](README.md#identity-format-preferences-content-negotiation)
  for the full vocabulary and semantics.

  Not affected: **IAM-user credentials** — there is no assumed-role session, so
  `aws-iam-role-arn` does not apply and the raw ARN is still issued.
- `--assume-role-session-name` and its library equivalents are retained, but now affect the
  identity only when you request `aws-arn`.

#### Retaining the previous behavior
Request `aws-arn` explicitly and the issued identity is byte-identical to v0.5.0 /
`v0.6.0-verifier`. No other change is needed.

| | |
|---|---|
| Environment (any language, no code change) | `S2IAM_IDENTITY_FORMAT_PREFERENCE=aws-arn` |
| CLI | `s2iam --identity-format-preference=aws-arn` |
| Go | `s2iam.WithIdentityFormatPreference("aws-arn")` |
| Python | `identity_format_preference=["aws-arn"]` |
| Java | `Options.withIdentityFormatPreference("aws-arn")` or `.identityFormatPreference("aws-arn")` |

On a fleet that also runs on GCP or Azure, keep the rest of the default list so those
providers stay pinned too:
`aws-arn,gcp-sa-email,gcp-sa-unique-id,azure-object-id`.

Under `aws-arn` the session name is part of the identity, so keep it stable: the
library-driven `AssumeRole` already uses a stable default (`s2iam-session`), EKS IRSA needs
`AWS_ROLE_SESSION_NAME` set, and an EC2 instance profile cannot be stabilized at all (its
session name is the instance id) — those workloads should adopt `aws-iam-role-arn`.

### Changed
- **The clients now send a complete identity-format preference, pinning every provider.**
  The built-in default is
  `[aws-iam-role-arn, aws-arn, gcp-sa-email, gcp-sa-unique-id, azure-object-id]`: every
  provider, each run ending at a format that is always available for that provider. The
  identity is therefore determined by the client and cannot move if a verifier operator
  changes the server-side default ordering. **The GCP and Azure entries reproduce the
  verifier's existing ordering, so no GCP or Azure identity changes** — they are named
  only to pin them. If you set your own preference, name every provider you run on for the
  same guarantee; a provider you omit falls back to the verifier's ordering.
- **The wire protocol is unchanged.** A request that sends no
  `X-S2IAM-Identity-Format-Preference` header still receives each provider's original
  default identity (`aws-arn` for AWS), so protocol-only clients are unaffected. Because
  the client preference outranks `VerifierConfig.DefaultIdentityFormats` and the clients
  now name every provider, that override only applies to requests which send no preference
  header at all.

## [v0.6.0-verifier]

> **Interim release — superseded by `v0.6.0`.** `v0.6.0-verifier` shipped the
> content-negotiation capability (client-selectable identity formats plus the verifier that
> honors them) while keeping every provider's default identity byte-identical to prior
> releases, so it stayed fully compatible with the auth server deployed at the time. It was
> step 1 of a staged rollout:
> 1. **`v0.6.0-verifier`** added negotiation with the historical defaults.
> 2. The auth-service verifier that honors the `X-S2IAM-Identity-Format-Preference` header
>    was deployed.
> 3. **`v0.6.0`** flipped the built-in AWS default to the session-stripped base IAM role
>    ARN (`[aws-iam-role-arn, aws-arn]`).
>
> Unless you are pinned to it deliberately, upgrade to `v0.6.0`.

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
- **Python:** the identity-format vocabulary (`FORMAT_AWS_ARN`,
  `FORMAT_AWS_IAM_ROLE_ARN`, `FORMAT_AWS_ROLE_ID`, `FORMAT_GCP_SA_EMAIL`,
  `FORMAT_GCP_SA_UNIQUE_ID`, `FORMAT_AZURE_OBJECT_ID`, `FORMAT_AZURE_RESOURCE_ID`) is now
  exported from the top-level `s2iam` package, so a preference can be named symbolically
  rather than hardcoded (parity with Go's `models` package and Java's `IdentityFormat`).

### Deprecated
- **Java:** the AWS `userId` identity-claim key (`AWSClient.CLAIM_USER_ID_LEGACY`). The STS
  user id is now populated under **both** `UserId` (`AWSClient.CLAIM_USER_ID`, matching the
  Go and Python clients) and the original `userId`, with the same value, so existing callers
  keep working. Read `UserId`; `userId` will be removed in a future major release.

### Fixed
- Authentication guide and OpenAPI examples use a UUID for `workspaceGroupID`. The auth server rejects non-UUID values such as `wg-...`.

## [v0.5.0] - 2026-06-16
### Added
- Optional AWS `RoleSessionName` when assuming a role (`WithAssumeRoleSessionName` in Go, `assume_role_session_name` in Python, `assumeRoleSessionName` / `Options.withAssumeRoleSessionName` in Java, `--assume-role-session-name` CLI flag).
- Documentation on AWS AssumeRole identity ARN matching for pre-provisioned database users (root README, Go/Java README).

### Changed
- AWS AssumeRole uses stable default session name `s2iam-session` when unset (replacing timestamp-based defaults in Go/Java). The resulting identity ARN is `arn:aws:sts::ACCOUNT:assumed-role/ROLE/s2iam-session`; pre-create database users and cloud principals to match that full ARN, or set an explicit session name.

### Fixed
- Java AWS client returns the STS assumed-role ARN from `GetCallerIdentity` (not the input IAM role ARN) when AssumeRole is used.

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

[v0.6.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.6.0-verifier...go/v0.6.0
[v0.6.0-verifier]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.5.0...go/v0.6.0-verifier
[v0.5.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.4.0...go/v0.5.0
[v0.4.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.3.0...go/v0.4.0
[v0.3.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.2.0...go/v0.3.0
[v0.2.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/go/v0.1.0...go/v0.2.0
[v0.1.0]: https://github.com/singlestore-labs/singlestore-auth-iam/compare/0.0.1...go/v0.1.0
