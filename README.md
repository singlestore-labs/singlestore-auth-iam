
# SingleStore Auth IAM

[![GoDoc](https://godoc.org/github.com/singlestore-labs/singlestore-auth-iam?status.svg)](https://pkg.go.dev/github.com/singlestore-labs/singlestore-auth-iam)
![Go unit tests](https://github.com/singlestore-labs/singlestore-auth-iam/actions/workflows/go.yml/badge.svg)
[![Go report card](https://goreportcard.com/badge/github.com/singlestore-labs/singlestore-auth-iam)](https://goreportcard.com/report/github.com/singlestore-labs/singlestore-auth-iam)
[![codecov](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam/branch/main/graph/badge.svg)](https://codecov.io/gh/singlestore-labs/singlestore-auth-iam)

## Overview

The `singlestore-auth-iam` library is designed to discover the IAM role from a cloud provider (AWS, GCP, Azure) and
then make a request that allows the SingleStore auth server to verify the IAM role. In return, the SingleStore
auth server will provide a JWT that can be used for:

- access to the SingleStore database (using the MySQL protocol and libraries); or
- making API calls via the API gateway.

## Features

- Multi-language support: Go, Python, Java, Node.js, and C++.
- Go command-line tool fetching and providing the JWT for other commands.

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
    "github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"
)

func main() {
    ctx := context.Background()
    jwt, err := s2iam.GetDatabaseJWT(ctx, "workspace-group-id")
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    fmt.Println("JWT:", jwt)
}
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements
Initial version of this library written by Gemini.
```

