SingleStore Auth IAM - Java
===========================

Status: ACTIVE DEVELOPMENT (parity tracking the Go reference). Breaking changes may still occur before GA.

Overview
--------
This Java library obtains short‑lived JWTs for SingleStore database (workspace group) or Management API access using native cloud provider identities (AWS / GCP / Azure). It auto‑detects the runtime cloud provider in seconds (target parity with Go implementation) and sends signed identity headers to the auth service which returns a JWT.

Quick Start
-----------
```java
import com.singlestore.s2iam.S2IAM;

// Database JWT (workspace group required)
String dbJwt = S2IAM.getDatabaseJWT("my-workspace-group-id");

// Management API JWT
String apiJwt = S2IAM.getAPIJWT();
```

Fluent Builder API
------------------
For advanced composition (assume role, custom timeout, explicit provider, custom server URL, GCP audience) use the builder:

```java
import com.singlestore.s2iam.*;

String jwt = S2IAMRequest.newRequest()
    .databaseWorkspaceGroup("my-workspace-group-id")     // or .api()
    .assumeRole("arn:aws:iam::123456789012:role/AppRole") // AWS ARN, GCP service account email, or Azure client ID
    .timeout(java.time.Duration.ofSeconds(5))
    .audience("https://authsvc.singlestore.com")          // GCP ONLY (see below)
    .get();
```

GCP Audience (GCP ONLY)
-----------------------
Use `.audience()` (builder) or `Options.withAudience()` (static API) ONLY when the detected (or explicitly provided) provider is GCP. The audience parameter tunes the GCP identity token audience. If you specify an audience and the provider is not GCP, the library throws `S2IAMException` immediately. (Older name `withGcpAudience` was renamed to `withAudience` and now enforces this validation.)

Assume Role / Impersonation
---------------------------
- AWS: Provide an IAM role ARN (e.g., `arn:aws:iam::ACCOUNT:role/RoleName`). Session duration fixed to 3600s (parity with Go). By default the issued identity is the raw STS assumed-role ARN; opt into the session-stripped base IAM role ARN via identity-format negotiation (below).
- GCP: Provide a service account email for impersonation.
- Azure: Provide a managed identity client (object) ID (UUID format).

Validation is strict; malformed identifiers raise `S2IAMException` before network calls.

Identity Format Preferences
---------------------------
By default the issued identity (JWT `sub`) is byte-identical to prior releases. Clients may opt into alternate representations by supplying an ordered preference list; the verifier picks the first form it supports and reports the choice in the response `identityFormat` field. See the [main README](../README.md#identity-format-preferences-content-negotiation) for the full vocabulary and semantics.

```java
// Adopt the session-stripped base IAM role ARN for AWS, falling back to the raw ARN.
String jwt = S2IAMRequest.newRequest()
    .databaseWorkspaceGroup("workspace-group-id")
    .assumeRole("arn:aws:iam::123456789012:role/AppRole")
    .identityFormatPreference("aws-iam-role-arn", "aws-arn")
    .get();

// Or with the static API:
String jwt2 = S2IAM.getDatabaseJWT("workspace-group-id",
    Options.withIdentityFormatPreference("aws-iam-role-arn", "aws-arn"));
```

Precedence is explicit option > `S2IAM_IDENTITY_FORMAT_PREFERENCE` (comma-separated) > built-in default.

Functional Options (Static API)
-------------------------------
```java
import com.singlestore.s2iam.options.Options;

String apiJwt = S2IAM.getAPIJWT(
    Options.withTimeout(Duration.ofSeconds(4)),
    Options.withAudience("https://authsvc.singlestore.com") // only if running on GCP
);
```

Operational Notes
-----------------
The library is fail-fast—unexpected conditions raise exceptions. Typical detection completes in under a second on real cloud instances; a higher ceiling timeout (10s) avoids false negatives on constrained environments.

API Summary
-----------
Core static methods:
- `S2IAM.getDatabaseJWT(workspaceGroupId, JwtOption...)`
- `S2IAM.getAPIJWT(JwtOption...)`
- `S2IAM.detectProvider()`

Builder:
- `S2IAMRequest.newRequest().databaseWorkspaceGroup(id)|api().assumeRole(id).audience(aud).timeout(d).provider(explicitProvider).serverUrl(url).get()`

Selected Options helpers:
- `Options.withTimeout(Duration)`
- `Options.withAudience(String)` (GCP only)
- `Options.withAssumeRole(String)`
- `Options.withIdentityFormatPreference(String...)`
- `Options.withServerUrl(String)`
- `Options.withProvider(CloudProviderClient)` (explicit injection / test)

Timeouts
--------
Default detection + HTTP call timeout: 10s. Override with `Options.withTimeout` or builder `.timeout()`.

License
-------
MIT (see root LICENSE file).
