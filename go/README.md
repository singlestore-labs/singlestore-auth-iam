# SingleStore Auth IAM - Go Client Library

[![GoDoc](https://godoc.org/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam?status.svg)](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam)
![Go unit tests](https://github.com/singlestore-labs/singlestore-auth-iam/actions/workflows/go.yml/badge.svg)
[![Go report card](https://goreportcard.com/badge/github.com/singlestore-labs/singlestore-auth-iam/go)](https://goreportcard.com/report/github.com/singlestore-labs/singlestore-auth-iam/go)

A Go client library for getting JWT tokens from SingleStore's IAM service when running in cloud environments (AWS, GCP, Azure).

## Installation

### Go Library

To install the Go library:
```sh
go get github.com/singlestore-labs/singlestore-auth-iam/go
```

### Command Line Tool

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

## Command Line Tool

The `s2iam` command line tool is documented in the [main README](../README.md#command-line-tool).

To install:
```bash
go install github.com/singlestore-labs/singlestore-auth-iam/go/cmd/s2iam@latest
```

## Supported Environments

The library automatically detects and works in:

- **AWS EC2 instances** with IAM roles
- **AWS Lambda functions** with execution roles
- **GCP Compute Engine** with service accounts
- **GCP Cloud Functions** with service accounts
- **Azure Virtual Machines** with managed identities
- **Azure Container Instances** with managed identities

## Cloud Provider Detection

The library automatically detects the cloud provider by checking environment variables and by reaching out to cloud metadata services:

- **AWS**: Checks for `AWS_EXECUTION_ENV` and metadata service at `169.254.169.254`
- **GCP**: Checks for `GCE_METADATA_HOST` and metadata service at `metadata.google.internal`
- **Azure**: Checks for `AZURE_ENV` and metadata service at `169.254.169.254`

## Testing

Run the tests:
```bash
go test ./...
```

## Documentation

- [API Documentation](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam/go/s2iam)
- [Solution Overview](SOLUTION_OVERVIEW.md)

## Support

For issues and questions:
- Create an issue on [GitHub](https://github.com/singlestore-labs/singlestore-auth-iam/issues)
- Check the [SingleStore documentation](https://docs.singlestore.com/)
