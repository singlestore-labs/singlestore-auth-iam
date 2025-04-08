# SingleStore Auth IAM

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
```sh
env GOBIN=/some/bin go install github.com/singlestore-labs/singlestore-auth-iam/cmd/s2iam@latest
```

## Usage

### Go

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

## Cloud Provider Detection

The library automatically detects the cloud provider by checking environment variables:

- AWS: Checks for `AWS_EXECUTION_ENV`
- GCP: Checks for `GCE_METADATA_HOST`
- Azure: Checks for `AZURE_ENV`

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements
Initial version of this library written by Gemini, rewritten by Claude 3.7 Sonnet
