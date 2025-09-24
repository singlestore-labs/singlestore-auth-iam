SingleStore Auth IAM - Java (Early Scaffold)
================================================

Status: EXPERIMENTAL / SCAFFOLD ONLY

This is the initial Java implementation scaffold intended to mirror the Go API.
Real cloud-provider detection logic still needs to be implemented. The structure
is in place so incremental provider logic and verification code can be added.

Primary goals achieved in this scaffold:

1. API Surface Parity (core convenience methods):
   S2IAM.detectProvider()
   S2IAM.getDatabaseJWT(workspaceGroupId, JwtOption...)
   S2IAM.getAPIJWT(JwtOption...)

2. Core domain model & interfaces:
   - CloudProviderType (enum)
   - CloudIdentity
   - CloudProviderClient (interface)
   - Logger (functional interface)

3. Options pattern (similar to Go functional options) via marker interfaces
   ProviderOption & JwtOption and concrete option helpers (WithTimeout, etc.)

4. Placeholder provider clients (AWS, GCP, Azure) with fast-fail detection.

5. Test pattern replicating Go/Python skip/fail logic using JUnit 5 assumptions.

What still needs real implementation:

- Actual FastDetect / Detect logic per provider.
- Assume role support for each provider.
- Identity header acquisition for each provider.
- Verifier (server-side) implementation.
- Coverage integration in CI similar to Go & Python.

Environment variable driven test semantics (mirrors other languages):
  S2IAM_TEST_CLOUD_PROVIDER=aws|gcp|azure
  S2IAM_TEST_ASSUME_ROLE=... (implies provider expected)
  S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE=aws|gcp|azure (detection expected, role not required)

Until real detection exists, tests will SKIP when no provider is detected and
no expectation env var is set; they FAIL if an expectation is set.

Example usage (once detection works):

```java
String jwt = S2IAM.getDatabaseJWT("my-workspace-group-id");
String apiJwt = S2IAM.getAPIJWT();
```

Custom server URL / provider injection:

```java
String jwt = S2IAM.getAPIJWT(
    Options.withServerUrl("https://authsvc.singlestore.com/auth/iam/:jwtType"),
    Options.withTimeout(Duration.ofSeconds(3))
);
```

Building & Testing:

Requires Java 11+ and Maven.

```bash
cd java
mvn -q test
```

Next Implementation Steps (suggested order):
1. Implement AWS metadata FastDetect & Detect.
2. Implement AWS STS-based identity header acquisition.
3. Add GCP & Azure detection.
4. Flesh out AssumeRole semantics.
5. Add verifier module (possibly separate package path).
6. Integrate into CI matrix (real cloud runners) mirroring Go/Python.

NOTE: Breaking changes are acceptable at this stage (no external users yet).
