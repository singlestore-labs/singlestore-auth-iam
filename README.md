# SingleStore Auth IAM

This repository contains tools for the SingleStore IAM authentication system.

[![GoDoc](https://godoc.org/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam?status.svg)](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam)
![Go unit tests](https://github.com/singlestore-labs/singlestore-auth-iam/actions/workflows/go.yml/badge.svg)
[![Go report card](https://goreportcard.com/badge/github.com/singlestore-labs/singlestore-auth-iam/go)](https://goreportcard.com/report/github.com/singlestore-labs/singlestore-auth-iam/go)
[![codecov](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam/branch/main/graph/badge.svg)](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam)

## Current Status

JWTs for engine (database) access and the management API are available.
APIs and language bindings may change before this is considered generally available.

Current language support: Go, Python, Java, shell.

## Overview

The `singlestore-auth-iam` library provides a seamless way to authenticate with SingleStore services using cloud provider IAM credentials. It automatically discovers your cloud environment (AWS, GCP, Azure) and obtains JWTs for:

- **Database Access**: Connect to [SingleStore Helios](https://www.singlestore.com/product-overview/) databases
- **Management API**: Make calls to the [SingleStore Management API](https://docs.singlestore.com/cloud/user-and-workspace-administration/management-api/)

### Key Features

- **Multi-language support**: Go (reference), Python, and Java implementations with converging functionality
- **Automatic detection**: Discovers cloud provider and obtains credentials automatically  
- **Role assumption**: Assume different roles/service accounts for enhanced security
- **Command-line tool**: Standalone CLI for scripts and CI/CD pipelines
- **Direct HTTP API**: OpenAPI spec for customers integrating without client libraries — see [API docs](docs/api/README.md) ([OpenAPI](docs/api/openapi.yaml), [HTML (Redoc)](https://redocly.github.io/redoc/?url=https://raw.githubusercontent.com/singlestore-labs/singlestore-auth-iam/main/docs/api/openapi.yaml))

### Future Plans
- Additional language support: Node.js and C++ (planned)


## Installation

### Go

To install the Go library:
```sh
go get github.com/singlestore-labs/singlestore-auth-iam/go
```

### Command Line Tool

To install the shell command:

```sh
go install github.com/singlestore-labs/singlestore-auth-iam/go/cmd/s2iam@latest
```

### Python

To install the Python library:
```bash
pip install singlestore-auth-iam
```

Or from source:
```bash
cd python
pip install -e .
```

### Java (Snapshot)

Until the first registered release, use the current snapshot version and ensure JDK 11+ (library is compiled targeting Java 11 for broad compatibility).

Maven:
```xml
<dependency>
	<groupId>com.singlestore</groupId>
	<artifactId>s2iam</artifactId>
	<version>0.0.1-SNAPSHOT</version>
</dependency>
```

Gradle (Groovy DSL):
```gradle
dependencies {
	implementation 'com.singlestore:s2iam:0.0.1-SNAPSHOT'
}
```

Gradle (Kotlin DSL):
```kotlin
dependencies {
	implementation("com.singlestore:s2iam:0.0.1-SNAPSHOT")
}
```

The Java API mirrors Go/Python convenience methods:
```java
String dbJwt = S2IAM.getDatabaseJWT("workspace-group-id");
String apiJwt = S2IAM.getAPIJWT();
```

For advanced composition (assume role, custom timeout, audience for GCP only) see `java/README.md`.

## Usage

### Go Library

```go
import "github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"

// Get JWT for database access
jwt, err := s2iam.GetDatabaseJWT(ctx, "workspace-group-id")

// Get JWT for API access
apiJWT, err := s2iam.GetAPIJWT(ctx)
```

**[📖 Full Go Documentation →](go/README.md)**

### Python Library

```python
import asyncio
import s2iam

# Get JWT for database access
jwt = await s2iam.get_jwt_database("workspace-group-id")

# Get JWT for API access
api_jwt = await s2iam.get_jwt_api()
```

**[📖 Full Python Documentation →](python/README.md)**

### Java Library

Add the Maven dependency (snapshot until first release):

```xml
<dependency>
	<groupId>com.singlestore</groupId>
	<artifactId>s2iam</artifactId>
	<version>0.0.1-SNAPSHOT</version>
</dependency>
```

Basic usage:

```java
import com.singlestore.s2iam.S2IAM;

// Detect provider & get database JWT
String jwt = S2IAM.getDatabaseJWT("workspace-group-id");

// Get API JWT
String apiJwt = S2IAM.getAPIJWT();
```

**Note:** Until GA, groupId/artifactId/version may change; pin exact versions and review release notes when updating.

Advanced (Builder API & Assume Role):

```java
import com.singlestore.s2iam.*;

String jwt = S2IAMRequest.newRequest()
	.databaseWorkspaceGroup("workspace-group-id") // or .api()
	.assumeRole("arn:aws:iam::123456789012:role/AppRole") // AWS, or service account email (GCP), or Azure client ID
	.audience("https://authsvc.singlestore.com")          // GCP ONLY; throws if non-GCP
	.timeout(java.time.Duration.ofSeconds(5))
	.get();
```

Audience (GCP ONLY): Supplying an audience when not on GCP raises an exception (renamed from withGcpAudience to withAudience and now enforced).

### Command Line Tool

#### Usage

```bash
# Get database JWT
s2iam --workspace-group-id=my-workspace

# Get API JWT
s2iam --jwt-type=api

# Use with environment variables for scripting
eval $(s2iam --env-status=STATUS --env-name=TOKEN --workspace-group-id=my-workspace)
echo $TOKEN
```

#### Advanced Usage

```bash
# AWS with assumed role (identity is the raw STS assumed-role ARN by default)
s2iam --provider=aws --assume-role=arn:aws:iam::123456789012:role/MyRole

# Opt into the session-stripped base IAM role ARN (arn:aws:iam::123456789012:role/MyRole)
s2iam --provider=aws --assume-role=arn:aws:iam::123456789012:role/MyRole \
      --identity-format-preference=aws-iam-role-arn,aws-arn

# GCP with service account impersonation
s2iam --provider=gcp --assume-role=service-account@project-id.iam.gserviceaccount.com

# Azure with managed identity
s2iam --provider=azure --assume-role=00000000-0000-0000-0000-000000000000

# Custom auth server
s2iam --server-url=https://auth.example.com/auth/iam/:jwtType

# Verbose logging
s2iam --verbose --workspace-group-id=my-workspace
```

#### Command Options

- `--jwt-type`: JWT type ('database' or 'api', default: 'database')
- `--workspace-group-id`: Workspace group ID (required for database JWT)
- `--provider`: Cloud provider ('aws', 'gcp', or 'azure', auto-detect if not specified)
- `--assume-role`: Role to assume (ARN for AWS, service account for GCP, managed identity for Azure)
- `--assume-role-session-name`: AWS STS `RoleSessionName` for `--assume-role`. Part of the identity under the `aws-arn` format; defaults to a stable value so the full ARN is pre-configurable. Does not affect the `aws-iam-role-arn` form. See [`aws-arn` and session names](#aws-arn-and-session-names)
- `--identity-format-preference`: Comma-separated, ordered list of preferred identity formats (e.g. `aws-iam-role-arn,aws-arn`). Also settable via `S2IAM_IDENTITY_FORMAT_PREFERENCE`. See [Identity format preferences](#identity-format-preferences-content-negotiation)
- `--server-url`: Authentication server URL
- `--env-name`: Environment variable name for JWT output
- `--env-status`: Environment variable name for status output
- `--print-sub`: Print the issued JWT's `sub` claim (the verified identity) to stderr; useful for confirming which identity format you'll be authorized as
- `--verbose`: Enable verbose logging
- `--timeout`: Timeout for operations (default: 10s)

## Supported Cloud Providers

- **AWS**: EC2 instances, Lambda functions, IAM roles, and role assumption
- **GCP**: Compute Engine, Cloud Functions, service accounts, and impersonation  
- **Azure**: Virtual Machines, Container Instances, managed identities

The libraries automatically detect the cloud provider and obtain appropriate credentials from metadata services.

### Identity format preferences (content negotiation)

The default authenticated identity (JWT `sub`) for each provider is:

| Provider | Default identity (JWT `sub`) |
|----------|------------------------------|
| AWS | Raw caller ARN from STS, e.g. `arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION` (or `arn:aws:iam::ACCOUNT:user/NAME` for IAM users) |
| GCP | Service account email, or the numeric unique id when the email is unverified |
| Azure | The `oid` principal (object id) |

Clients can **opt into** alternate representations by sending an ordered preference
list. The verifier picks the first format it supports and can derive for the
authenticated identity, and reports the choice back in the response `identityFormat`
field. Negotiation only reorders among representations the verifier has already derived
for the same identity — it never broadens a match or crosses identities, and it always
falls back to the default (and ultimately the always-valid floor) when a preference
cannot be honored.

#### Format vocabulary

`*` marks the default format for each CSP — the `sub` you get when you send no preference.

| Format token | CSP | Meaning | Example `sub` |
|--------------|-----|---------|---------------|
| `aws-arn` * | AWS | Raw STS/IAM caller ARN; session-bearing for assumed roles (pre-configurable only when the session name is stable — see below). Always available (floor / default) | assumed role: `arn:aws:sts::123456789012:assumed-role/MyRole/MySession`; IAM user: `arn:aws:iam::123456789012:user/MyUser` |
| `aws-iam-role-arn` | AWS | Session-stripped base IAM role ARN `arn:aws:iam::ACCOUNT:role/ROLE`; assumed-role sessions only | `arn:aws:iam::123456789012:role/MyRole` |
| `aws-role-id` | AWS | Stable `RoleId` (`AROA…`, prefix of the STS `UserId`); assumed-role sessions only | `AROAEXAMPLEID1234567` |
| `gcp-sa-email` * | GCP | The service account's own email (the `…@PROJECT.iam.gserviceaccount.com` identity); only when the token carries that `email` claim with `email_verified` | `my-sa@my-project.iam.gserviceaccount.com` |
| `gcp-sa-unique-id` | GCP | Numeric service-account unique id; always available (floor) | `103547991597142817347` |
| `azure-object-id` * | Azure | `oid` principal (object id); always available (floor / default) | `11111111-2222-3333-4444-555555555555` |
| `azure-resource-id` | Azure | `xms_mirid` resource id; user-assigned managed identity only | `/subscriptions/<sub>/resourcegroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-mi` |

#### `aws-arn` and session names

Because the `sub` must be pre-configured as a cloud principal / database user, the
session-bearing `aws-arn` form is only usable when the session name is **stable**:

- **IAM user** — the ARN has no session; always stable.
- **Library-driven `AssumeRole`** (`WithAssumeRole`) — the library uses a stable default
  session name (`s2iam-session`), so the full ARN is deterministic. Set your own with
  `WithAssumeRoleSessionName` (Go), `assume_role_session_name` (Python),
  `Options.withAssumeRoleSessionName(...)` / `.assumeRoleSessionName(...)` (Java), or
  `--assume-role-session-name` (CLI).
- **EKS IRSA** — set `AWS_ROLE_SESSION_NAME` to stabilize the session name.
- **EC2 instance profile** — the session name is the instance id and cannot be
  stabilized; use `aws-iam-role-arn` instead.

#### Selecting a preference

Set the preference (highest priority first) programmatically, via CLI, or via environment:

```bash
# Adopt the session-stripped base IAM role ARN for AWS, fall back to the raw ARN
export S2IAM_IDENTITY_FORMAT_PREFERENCE="aws-iam-role-arn,aws-arn"
s2iam --workspace-group-id=my-workspace

# Or per-invocation
s2iam --identity-format-preference="aws-iam-role-arn,aws-arn" --workspace-group-id=my-workspace

# Confirm which identity you'll be authorized as (prints the JWT `sub` to stderr)
s2iam --identity-format-preference="aws-iam-role-arn,aws-arn" --workspace-group-id=my-workspace --print-sub >/dev/null
```

If you only have the raw JWT (e.g. a protocol-only client without the CLI), decode the
payload to read the issued `sub` directly (handling base64url padding):

```bash
echo "$TOKEN" | cut -d. -f2 | python3 -c 'import sys,base64,json; d=sys.stdin.read().strip(); d+="="*(-len(d)%4); print(json.loads(base64.urlsafe_b64decode(d))["sub"])'
```

Decode the issued JWT, inspect its `sub`, and register the cloud principal / database
user for the exact `sub` form you intend to use so the identity you authorize as matches
what you configured.

Precedence is **explicit option > `S2IAM_IDENTITY_FORMAT_PREFERENCE` > built-in default**.
Language options: `WithIdentityFormatPreference(...)` (Go),
`identity_format_preference=[...]` (Python),
`Options.withIdentityFormatPreference(...)` / `.identityFormatPreference(...)` (Java).

#### AWS: base IAM role ARN vs. raw ARN

With the preference `["aws-iam-role-arn", "aws-arn"]`, every AWS STS assumed-role
session — EC2 instance profile, EKS IRSA, or explicit `AssumeRole` — collapses to the
**base IAM role ARN**:

| Credentials | `sub` with `aws-iam-role-arn` preference |
|-------------|------------------------------------------|
| EC2 instance profile `MyRole` | `arn:aws:iam::123456789012:role/MyRole` |
| EKS IRSA role `MyRole` | `arn:aws:iam::123456789012:role/MyRole` |
| `AssumeRole arn:aws:iam::123456789012:role/MyRole` (any session name) | `arn:aws:iam::123456789012:role/MyRole` |

The caller-chosen STS session name is **not** part of the base role ARN; it is not a
trustworthy authorization boundary (the IAM role is gated by its trust policy), and AWS
guarantees role names are unique within an account. Note the base role ARN is path-less:
a role under a non-root IAM path (e.g. `/team/MyRole`) is represented as
`arn:aws:iam::ACCOUNT:role/MyRole`. Register the cloud principal and create database
users to match whichever `sub` form you choose.

The raw STS assumed-role ARN, session name, and STS `UserId` (whose prefix is the stable
`RoleId`) always remain available in the identity's additional claims for auditing,
regardless of the selected format.

## Documentation

- **[Go Library Documentation](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam) and [README](go/README.md)** - Complete Go API reference and examples
- **[Python Library Documentation](python/README.md)** - Complete Python API reference and examples
- **Java**: See inline Javadoc and `[README](java/README.md)` (implementation evolving pre-GA)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
