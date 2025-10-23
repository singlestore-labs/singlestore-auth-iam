# SingleStore Auth IAM

This repository contains tools for the SingleStore IAM authentication system.

[![GoDoc](https://godoc.org/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam?status.svg)](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam)
![Go unit tests](https://github.com/singlestore-labs/singlestore-auth-iam/actions/workflows/go.yml/badge.svg)
[![Go report card](https://goreportcard.com/badge/github.com/singlestore-labs/singlestore-auth-iam/go)](https://goreportcard.com/report/github.com/singlestore-labs/singlestore-auth-iam/go)
[![codecov](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam/branch/main/graph/badge.svg)](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam)

## Current Status

JWTs for engine access are ready for testing.
JWTs for the management API are not yet available.
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

- **[Go Library Documentation](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam) and [README](go/README.md)** - Complete Go API reference and examples
- **[Python Library Documentation](python/README.md)** - Complete Python API reference and examples
- **Java**: See inline Javadoc and `[README](java/README.md)` (implementation evolving pre-GA)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
