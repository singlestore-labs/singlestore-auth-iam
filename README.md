# SingleStore Auth IAM

This repository contains tools for the SingleStore IAM authentication system.

[![GoDoc](https://godoc.org/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam?status.svg)](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam)
![Go unit tests](https://github.com/singlestore-labs/singlestore-auth-iam/actions/workflows/go.yml/badge.svg)
[![Go report card](https://goreportcard.com/badge/github.com/singlestore-labs/singlestore-auth-iam/go)](https://goreportcard.com/report/github.com/singlestore-labs/singlestore-auth-iam/go)
[![codecov](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam/branch/main/graph/badge.svg)](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam)

## Current status

This service is not yet available. This library may be updated before the service becomes available.

## Overview

The `singlestore-auth-iam` library provides a seamless way to authenticate with SingleStore services using cloud provider IAM credentials. It automatically discovers your cloud environment (AWS, GCP, Azure) and obtains JWT tokens for:

- **Database Access**: Connect to [SingleStore Helios](https://www.singlestore.com/product-overview/) databases
- **Management API**: Make calls to the [SingleStore Management API](https://docs.singlestore.com/cloud/user-and-workspace-administration/management-api/)

### Key Features

- **Multi-language support**: Go and Python libraries with identical functionality
- **Automatic detection**: Discovers cloud provider and obtains credentials automatically  
- **Role assumption**: Assume different roles/service accounts for enhanced security
- **Command-line tool**: Standalone CLI for scripts and CI/CD pipelines

### Future Plans
- Additional language support: Java, Node.js, and C++ (coming soon)

## Current Status

This service is not yet available. This library may be updated before the service becomes available.

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

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
