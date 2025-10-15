# SingleStore Auth IAM

This repository contains tools for the SingleStore IAM authentication system.

[![GoDoc](https://godoc.org/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam?status.svg)](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam)
![Go unit tests](https://github.com/singlestore-labs/singlestore-auth-iam/actions/workflows/go.yml/badge.svg)
[![Go report card](https://goreportcard.com/badge/github.com/singlestore-labs/singlestore-auth-iam/go)](https://goreportcard.com/report/github.com/singlestore-labs/singlestore-auth-iam/go)
[![codecov](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam/branch/main/graph/badge.svg)](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam)

## Current Status

JWTs for engine access are ready for testing.
JWTs for the management API are not yet available.
APIs and language bindings may change before this is considered generally avaialble.

## Overview
### Cloud Provider Detection (Parity Overview)

All language implementations follow the same logical ordering to identify the current cloud environment:

1. Fast path hints (environment variables, explicit credential presence, test-only system properties). Returns immediately on first match.
2. Concurrent metadata detection across AWS, GCP, Azure. Each provider performs a single metadata probe (plus minimal classification calls) with a shared detection timeout.
3. First successful provider cancels the remaining attempts.

Timeouts:
- Java & Python use a 10s upper bound for detection orchestration (Java via `Timeouts.DETECT`, Python via a global deadline). Healthy real-cloud responses are typically <100ms; the timeout should rarely be hit.
- Identity/token fetch operations use a separate 10s baseline (`Timeouts.IDENTITY` in Java) to allow STS / MSI / GCP identity token retrieval.

Observability:
- Python exposes a `provider_status` list (phase, provider, status, elapsed_ms, error).
- Java now offers `S2IAM.detectProviderWithStatus` returning a structured attempt list (`phase=fast|detect`, `status=success|error`).

Environment Flags:
- `S2IAM_DEBUGGING=true` enables human-readable log messages.
- `S2IAM_DEBUG_TIMING=true` (Java & Python) includes per-attempt duration metrics without requiring always-on verbose logs.

Design Principles:
- Fail fast but do not prematurely declare failure while a plausible provider may still respond within the 10s window.
- Avoid hidden retries for initial detection to surface latency issues early (exception: targeted Azure MSI throttling handling lives in provider-specific logic in Python; Java may add symmetric logic if evidence appears).
- Each provider’s detection attempt is a single network round trip (plus a lightweight supplementary call for Azure classification) to keep CI cycles short.


The `singlestore-auth-iam` library provides a seamless way to authenticate with SingleStore services using cloud provider IAM credentials. It automatically discovers your cloud environment (AWS, GCP, Azure) and obtains JWTs for:

- **Database Access**: Connect to [SingleStore Helios](https://www.singlestore.com/product-overview/) databases
- **Management API**: Make calls to the [SingleStore Management API](https://docs.singlestore.com/cloud/user-and-workspace-administration/management-api/)

### Key Features

- **Multi-language support**: Go (reference), Python, and Java implementations with converging functionality
- **Automatic detection**: Discovers cloud provider and obtains credentials automatically  
- **Role assumption**: Assume different roles/service accounts for enhanced security
- **Command-line tool**: Standalone CLI for scripts and CI/CD pipelines

### Future Plans
- Additional language support: Node.js and C++ (planned)


## Installation

### Go

To install the Go library:
```sh
go get github.com/singlestore-labs/singlestore-auth-iam/go
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

#### Installation

```bash
go install github.com/singlestore-labs/singlestore-auth-iam/go/cmd/s2iam@latest
```

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
# AWS with assumed role
s2iam --provider=aws --assume-role=arn:aws:iam::123456789012:role/MyRole

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
- `--server-url`: Authentication server URL
- `--env-name`: Environment variable name for JWT output
- `--env-status`: Environment variable name for status output
- `--verbose`: Enable verbose logging
- `--timeout`: Timeout for operations (default: 10s)

## Supported Cloud Providers

- **AWS**: EC2 instances, Lambda functions, IAM roles, and role assumption
- **GCP**: Compute Engine, Cloud Functions, service accounts, and impersonation  
- **Azure**: Virtual Machines, Container Instances, managed identities

The libraries automatically detect the cloud provider and obtain appropriate credentials from metadata services.

## Documentation

- **[Go Library Documentation](go/README.md)** - Complete Go API reference and examples
- **[Python Library Documentation](python/README.md)** - Complete Python API reference and examples
- **Java**: See inline Javadoc and `java/README.md` (implementation evolving pre-GA)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
