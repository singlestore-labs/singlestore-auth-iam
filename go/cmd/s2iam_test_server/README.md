## s2iam_test_server - Test Server

The `s2iam_test_server` is a test server that facilitates writing client tests in various languages. It simulates the SingleStore IAM authentication server behavior.

### Installation

```bash
go install github.com/singlestore-labs/singlestore-auth-iam/go/cmd/s2iam_test_server@latest
```

### Usage

Start the test server:
```bash
s2iam_test_server
```

The server will start on port 8080 by default and provide the following endpoints:
- `http://localhost:8080/auth/iam/:jwtType` - Authentication endpoint
- `http://localhost:8080/info/public-key` - Get server's public key
- `http://localhost:8080/info/requests` - View request log
- `http://localhost:8080/health` - Health check

### Testing Different Scenarios

Simulate verification failure:
```bash
s2iam_test_server --fail-verification
```

Return empty JWT:
```bash
s2iam_test_server --return-empty-jwt
```

Return custom error:
```bash
s2iam_test_server --return-error --error-code=503 --error-message="Service unavailable"
```

Require specific GCP audience:
```bash
s2iam_test_server --required-audience=https://myapp.example.com
```

### Options

- `--port`: Port to listen on (default: 8080)
- `--key-size`: RSA key size (default: 2048)
- `--fail-verification`: Fail verification for all requests
- `--return-empty-jwt`: Return empty JWT in response
- `--return-error`: Return an error response
- `--error-code`: HTTP error code to return (default: 500)
- `--error-message`: Error message to return
- `--required-audience`: Required audience value for GCP tokens
- `--azure-tenant`: Azure tenant ID (default: "common")
- `--token-expiry`: Token expiry duration (default: 1h)
- `--allowed-audiences`: Comma-separated list of allowed audiences
- `--verbose`: Enable verbose logging

### Using the Test Server for Client Testing

The test server can be used to test clients in various languages:

#### Python Example

```python
import requests
import subprocess

# Start the test server
server = subprocess.Popen(['s2iam_test_server', '--port=8080'])

try:
    # Get JWT using your Python client
    headers = {
        # Add appropriate cloud provider headers
    }
    
    response = requests.post(
        'http://localhost:8080/auth/iam/database',
        headers=headers,
        params={'workspaceGroupID': 'test-workspace'}
    )
    
    jwt = response.json()['jwt']
    print(f"Got JWT: {jwt}")
    
finally:
    server.terminate()
```

#### JavaScript Example

```javascript
const { spawn } = require('child_process');
const axios = require('axios');

// Start the test server
const server = spawn('s2iam_test_server', ['--port=8080']);

// Wait for server to start
await new Promise(resolve => setTimeout(resolve, 1000));

try {
    // Get JWT using your JavaScript client
    const response = await axios.post(
        'http://localhost:8080/auth/iam/database',
        null,
        {
            headers: {
                // Add appropriate cloud provider headers
            },
            params: {
                workspaceGroupID: 'test-workspace'
            }
        }
    );
    
    const jwt = response.data.jwt;
    console.log(`Got JWT: ${jwt}`);
    
} finally {
    server.kill();
}
```

### Docker Usage

The test server can be containerized for easier cross-language testing:

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
```
