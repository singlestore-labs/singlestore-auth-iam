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
- AWS: Provide an IAM role ARN (e.g., `arn:aws:iam::ACCOUNT:role/RoleName`). Session duration fixed to 3600s (parity with Go). Session name prefix: `SingleStoreAuth-`.
- GCP: Provide a service account email for impersonation.
- Azure: Provide a managed identity client (object) ID (UUID format).

Validation is strict; malformed identifiers raise `S2IAMException` before network calls.

Functional Options (Static API)
-------------------------------
```java
import com.singlestore.s2iam.options.Options;

String apiJwt = S2IAM.getAPIJWT(
    Options.withTimeout(Duration.ofSeconds(4)),
    Options.withAudience("https://authsvc.singlestore.com") // only if running on GCP
);
```

Detection & Performance
-----------------------
Detection proceeds in two phases:
1. Fast phase (serial) – very quick heuristics per provider.
2. Full phase (concurrent with 5s default timeout) – parallel deeper probes.

The first positive result short‑circuits. Typical success latency on real cloud instances is under a second (target parity with Go).

Operational Notes
-----------------
All outbound requests include `User-Agent: s2iam-java/<impl-version>`. The library is fail-fast—any unexpected condition raises an exception rather than logging a warning.

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
- `Options.withServerUrl(String)`
- `Options.withProvider(CloudProviderClient)` (explicit injection / test)

Timeouts
--------
Default detection + HTTP call timeout: 5s (aligned to Go reference). Override with `Options.withTimeout` or builder `.timeout()`.

Testing (Minimal)
-----------------
Run the unit/integration tests (requires Go toolchain for the local test server):
```bash
cd java && mvn -q test
```

License
-------
MIT (see root LICENSE file).
