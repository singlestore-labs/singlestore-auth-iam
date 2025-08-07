# s2iam_test_server - Test Server

The `s2iam_test_server` is a test server that facilitates writing and testing client implementations for SingleStore IAM authentication in various languages. It simulates the SingleStore authentication server behavior and provides flexible configuration options for testing different scenarios.

## Installation

```bash
go install github.com/singlestore-labs/singlestore-auth-iam/go/cmd/s2iam_test_server@latest
```

## Quick Start

Start the test server with default settings:
```bash
s2iam_test_server
```

The server will start on port 8080 by default. Once it's fully ready to accept requests, it outputs JSON-formatted server information:
```json
{
  "server_info": {
    "port": 8080,
    "endpoints": {
      "auth": "http://localhost:8080/auth/iam/:jwtType",
      "public_key": "http://localhost:8080/info/public-key",
      "requests": "http://localhost:8080/info/requests",
      "health": "http://localhost:8080/health"
    },
    "config": {
      "fail_verification": false,
      "return_empty_jwt": false,
      "return_error": false,
      "error_code": 500,
      "token_expiry": "1h0m0s"
    }
  }
}
```

**Note**: The server automatically performs a health check on itself before printing this JSON output, ensuring that when you parse this information, the server is guaranteed to be ready to accept requests.

## Endpoints

### Authentication Endpoint
- **URL**: `/auth/iam/{jwtType}`
- **Method**: GET/POST
- **Parameters**: 
  - `workspaceGroupID` (query parameter)
  - `jwtType` (path parameter): Type of JWT to generate (e.g., "database", "api")
- **Response**: JSON object with a `jwt` field containing the generated JWT token
  ```json
  {
    "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```

### Public Key Endpoint
- **URL**: `/info/public-key`
- **Method**: GET
- **Response**: RSA public key in PEM format (text/plain)
  ```
  -----BEGIN RSA PUBLIC KEY-----
  MIIBCgKCAQEA...
  -----END RSA PUBLIC KEY-----
  ```

### Request Log Endpoint
- **URL**: `/info/requests`
- **Method**: GET
- **Response**: JSON array of all received requests with details

### Health Check Endpoint
- **URL**: `/health`
- **Method**: GET
- **Response**: JSON object with server status
  ```json
  {
    "status": "healthy",
    "time": "2025-01-15T10:30:00Z",
    "config": {
      "port": 8080,
      "failVerification": false,
      "returnEmptyJWT": false,
      "returnError": false
    }
  }
  ```

## Configuration Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 8080 | Port to listen on (use 0 for random port) |
| `--key-size` | 2048 | RSA key size in bits |
| `--fail-verification` | false | Fail verification for all requests |
| `--return-empty-jwt` | false | Return empty JWT in response |
| `--return-error` | false | Return an error response |
| `--error-code` | 500 | HTTP error code to return (when --return-error) |
| `--error-message` | "Internal Server Error" | Error message to return |
| `--required-audience` | "" | Required audience value for GCP tokens |
| `--azure-tenant` | "common" | Azure tenant ID |
| `--token-expiry` | 1h | Token expiry duration |
| `--allowed-audiences` | "https://authsvc.singlestore.com" | Comma-separated list of allowed audiences |
| `--verbose` | false | Enable verbose logging |

## Testing Scenarios

### Basic Usage

```bash
# Start with default configuration
s2iam_test_server

# Use a random port
s2iam_test_server --port=0

# Enable verbose logging
s2iam_test_server --verbose
```

### Error Simulation

```bash
# Simulate verification failure
s2iam_test_server --fail-verification

# Return empty JWT
s2iam_test_server --return-empty-jwt

# Return custom error
s2iam_test_server --return-error --error-code=503 --error-message="Service unavailable"
```

### Cloud Provider Configuration

```bash
# Require specific GCP audience
s2iam_test_server --required-audience=https://myapp.example.com

# Configure Azure tenant
s2iam_test_server --azure-tenant=12345678-1234-1234-1234-123456789012

# Set custom allowed audiences
s2iam_test_server --allowed-audiences=https://authsvc.singlestore.com,https://myapp.com
```

## Client Integration Examples

### Python Example

```python
import requests
import subprocess
import json

# Start the test server with a random port
server = subprocess.Popen(['s2iam_test_server', '--port=0'], 
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

# Read and parse the server output
# The server waits until it's ready before printing, so no sleep needed
output_line = server.stdout.readline()
server_info = json.loads(output_line)['server_info']
port = server_info['port']

try:
    # For AWS IAM authentication
    headers = {
        'X-Amz-Security-Token': 'your-session-token',
        'X-Amz-Date': '20250113T123456Z',
        'Authorization': 'AWS4-HMAC-SHA256 Credential=...'
    }
    
    response = requests.post(
        f'http://localhost:{port}/auth/iam/database',
        headers=headers,
        params={'workspaceGroupID': 'test-workspace'}
    )
    
    jwt = response.json()['jwt']
    print(f"Got JWT: {jwt}")
    
    # Get the public key for JWT verification
    public_key_response = requests.get(f'http://localhost:{port}/info/public-key')
    public_key_pem = public_key_response.text
    
finally:
    server.terminate()
```

### JavaScript/Node.js Example

```javascript
const { spawn } = require('child_process');

// Start the test server
const server = spawn('s2iam_test_server', ['--port=0']);

// Parse server output to get port
// The server is ready when it prints the JSON output
server.stdout.once('data', async (data) => {
    const output = data.toString();
    const serverInfo = JSON.parse(output).server_info;
    const port = serverInfo.port;
    
    try {
        // For GCP authentication
        const url = new URL(`http://localhost:${port}/auth/iam/api`);
        url.searchParams.set('workspaceGroupID', 'test-workspace');
        
        const response = await fetch(url, {
            method: "POST",
            headers: {
                'Metadata-Flavor': 'Google',
                'Authorization': 'Bearer gcp-token'
            }
        });
        
        const jwt = (await response.json()).jwt;
        console.log(`Got JWT: ${jwt}`);
        
    } finally {
        server.kill();
    }
});
```

### Go Example

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "os/exec"
    "time"
)

func main() {
    // Start test server
    cmd := exec.Command("s2iam_test_server", "--port=0")
    stdout, _ := cmd.StdoutPipe()
    _ = cmd.Start()
    
    // Parse server info
    var serverInfo struct {
        ServerInfo struct {
            Port int `json:"port"`
        } `json:"server_info"`
    }
    
    decoder := json.NewDecoder(stdout)
    _ = decoder.Decode(&serverInfo)
    port := serverInfo.ServerInfo.Port
    
    // Make authentication request
    client := &http.Client{Timeout: 5 * time.Second}
    
    req, _ := http.NewRequest("POST", 
        fmt.Sprintf("http://localhost:%d/auth/iam/database", port), 
        nil)
    
    // Add Azure headers
    req.Header.Set("X-Ms-Identity-Provider", "azure")
    req.Header.Set("Authorization", "Bearer azure-token")
    
    resp, _ := client.Do(req)
    defer resp.Body.Close()
    
    var result map[string]string
    _ = json.NewDecoder(resp.Body).Decode(&result)
    
    fmt.Printf("Got JWT: %s\n", result["jwt"])
    
    // Cleanup
    _ = cmd.Process.Kill()
}
```

## Docker Usage

Create a Dockerfile for containerized testing:

```dockerfile
FROM golang:1.21-alpine
WORKDIR /app
COPY . .
RUN go build -o s2iam_test_server ./cmd/s2iam_test_server
EXPOSE 8080
CMD ["./s2iam_test_server"]
```

Build and run:
```bash
docker build -t s2iam-test-server .
docker run -p 8080:8080 s2iam-test-server

# With custom configuration
docker run -p 8080:8080 s2iam-test-server \
    --verbose \
    --token-expiry=30m \
    --allowed-audiences=https://myapp.com
```

## Expected Headers by Provider

When testing authentication, use the appropriate headers for each cloud provider:

### AWS
- `X-Amz-Security-Token`: Session token (if using temporary credentials)
- `X-Amz-Date`: Request timestamp
- `Authorization`: AWS Signature v4 authorization header

### GCP
- `Metadata-Flavor`: Should be "Google"
- `Authorization`: Bearer token with GCP access token

### Azure
- `X-Ms-Identity-Provider`: Should be "azure"
- `Authorization`: Bearer token with Azure access token

## JWT Token Structure

The generated JWT tokens contain the following claims:
- `sub`: Cloud provider identifier
- `provider`: Cloud provider name (aws, gcp, azure)
- `accountID`: Account/project ID
- `region`: Region (if applicable)
- `resourceType`: Resource type
- `jwtType`: Type specified in the URL path
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp

## Tips for Testing

1. **Random Port Selection**: Use `--port=0` to let the server choose a random available port, useful for parallel testing.

2. **No Wait Required**: The server performs a self-health check before printing the JSON output, guaranteeing it's ready to accept requests. Tests can parse the JSON and immediately start making requests without any additional wait time.

3. **Parse Server Output**: The server outputs JSON-formatted information when ready, making it easy to programmatically determine the port and endpoints.

4. **Verbose Logging**: Use `--verbose` to see detailed request processing information during development.

5. **Request Logging**: Use the `/info/requests` endpoint to inspect all requests received by the server, helpful for debugging client implementations.

6. **JWT Verification**: Retrieve the public key from `/info/public-key` to verify the generated JWTs in your tests.

7. **Error Simulation**: Use error flags to test your client's error handling capabilities.

