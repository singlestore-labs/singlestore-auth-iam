# SingleStore Auth IAM

This repository contains tools for the SingleStore IAM authentication system.

[![GoDoc](https://godoc.org/github.com/singlestore-labs/singlestore-auth-iam?status.svg)](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam)
![Go unit tests](https://github.com/singlestore-labs/singlestore-auth-iam/actions/workflows/go.yml/badge.svg)
[![Go report card](https://goreportcard.com/badge/github.com/singlestore-labs/singlestore-auth-iam)](https://goreportcard.com/report/github.com/singlestore-labs/singlestore-auth-iam)
[![codecov](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam/branch/main/graph/badge.svg)](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam)

## Overview

The `singlestore-auth-iam` library discovers the IAM role from a cloud provider (AWS, GCP, Azure) and
makes a request that allows the SingleStore auth server to verify the IAM role. In return, the SingleStore
auth server provides a JWT that can be used for:

- Access to the SingleStore database (using the MySQL protocol and libraries)
- Making API calls via the API gateway

## Features

- Go library for JWT authentication
- Support for AWS, GCP, and Azure cloud providers
- Customizable authentication server URL and GCP audience
- Command-line tool for fetching and providing the JWT for other commands
- Role assumption capabilities (assume different roles/service accounts before requesting the JWT)

### Future Plans
- Multi-language support: Python, Java, Node.js, and C++ (coming soon)

## Installation

### Go

To install the Go library:
```sh
go get github.com/singlestore-labs/singlestore-auth-iam/go
```

To install the command:
```bash
go install github.com/singlestore-labs/singlestore-auth-iam/go/cmd/s2iam@latest
```

## Usage

### Go Library

Example usage in Go:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"
)

func main() {
    ctx := context.Background()
    
    // Get JWT for database access
    jwt, err := s2iam.GetDatabaseJWT(ctx, "workspace-group-id")
    if err != nil {
        log.Fatalf("Error getting database JWT: %v", err)
    }
    fmt.Println("Database JWT:", jwt)
    
    // Get JWT for API access
    apiJWT, err := s2iam.GetAPIJWT(ctx)
    if err != nil {
        log.Fatalf("Error getting API JWT: %v", err)
    }
    fmt.Println("API JWT:", apiJWT)
    
    // Using options
    customJWT, err := s2iam.GetDatabaseJWT(
        ctx,
        "workspace-group-id",
        s2iam.WithExternalServerURL("https://custom-auth.singlestore.com/auth/iam"),
        s2iam.WithGCPAudience("custom-audience"),
    )
    if err != nil {
        log.Fatalf("Error getting custom JWT: %v", err)
    }
    fmt.Println("Custom JWT:", customJWT)
    
    // Assume a different role before getting a JWT
    // For AWS, provide a role ARN
    assumedRoleJWT, err := s2iam.GetDatabaseJWT(
        ctx,
        "workspace-group-id",
        s2iam.WithAssumeRole("arn:aws:iam::123456789012:role/RoleToAssume"),
    )
    if err != nil {
        log.Fatalf("Error getting JWT with assumed role: %v", err)
    }
    fmt.Println("JWT with assumed role:", assumedRoleJWT)
}
```

### Role Assumption

The library supports assuming different roles/identities before requesting a JWT. This is useful when your application needs to request JWTs with permissions granted to a different role than the one it's running under.

- **AWS**: Provide a role ARN to assume a different IAM role
- **GCP**: Provide a service account email to impersonate that service account
- **Azure**: Provide a managed identity client ID to use a specific managed identity

Example with role assumption:

```go
// AWS role assumption
awsJWT, err := s2iam.GetDatabaseJWT(
    ctx,
    "workspace-group-id",
    s2iam.WithAssumeRole("arn:aws:iam::123456789012:role/RoleToAssume"),
)

// GCP service account impersonation
gcpJWT, err := s2iam.GetDatabaseJWT(
    ctx,
    "workspace-group-id",
    s2iam.WithAssumeRole("service-account@project-id.iam.gserviceaccount.com"),
)

// Azure managed identity selection
azureJWT, err := s2iam.GetDatabaseJWT(
    ctx,
    "workspace-group-id",
    s2iam.WithAssumeRole("12345678-1234-1234-1234-123456789012"),
)
```

### S2IAM Command Line Tools

The `s2iam` command is a standalone client that obtains JWT tokens from the SingleStore IAM authentication service.

#### Basic Usage

Get a database JWT for a workspace:
```bash
s2iam --workspace-group-id=my-workspace
```

Get an API JWT:
```bash
s2iam --jwt-type=api
```

#### Environment Variable Output

To set the results in environment variables for use in scripting:

```bash
# Set up environment variables
eval $(s2iam --env-status=STATUS --env-name=TOKEN --workspace-group-id=my-workspace)

# Use the token
echo $TOKEN
# Check status (0 = success, 1 = error)
echo $STATUS
```

#### Advanced Options

Use a specific provider and role:
```bash
# AWS with assumed role
s2iam --provider=aws --assume-role=arn:aws:iam::123456789012:role/MyRole

# GCP with custom audience
s2iam --provider=gcp --gcp-audience=https://myapp.example.com

# Azure with managed identity
s2iam --provider=azure --assume-role=00000000-0000-0000-0000-000000000000
```

Use a custom authentication server:
```bash
s2iam --server-url=https://auth.example.com/auth/iam/:jwtType
```

Enable verbose logging:
```bash
s2iam --verbose --workspace-group-id=my-workspace
```

#### Options

- `--jwt-type`: JWT type ('database' or 'api', default: 'database')
- `--workspace-group-id`: Workspace group ID (required for database JWT)
- `--gcp-audience`: GCP audience for identity token
- `--provider`: Cloud provider ('aws', 'gcp', or 'azure', auto-detect if not specified)
- `--assume-role`: Role to assume (ARN for AWS, service account for GCP, managed identity for Azure)
- `--timeout`: Timeout for operations (default: 10s)
- `--server-url`: Authentication server URL
- `--env-name`: Environment variable name for JWT output
- `--env-status`: Environment variable name for status output
- `--verbose`: Enable verbose logging
- `--force-detect`: Force provider detection even if provider is specified

## Cloud Provider Detection

The library automatically detects the cloud provider by checking environment variables:

- AWS: Checks for `AWS_EXECUTION_ENV`
- GCP: Checks for `GCE_METADATA_HOST`
- Azure: Checks for `AZURE_ENV`

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements
Initial version of this library written by Gemini, rewritten by Claude 3.7 Sonnet
