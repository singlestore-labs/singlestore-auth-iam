# SingleStore Auth IAM - Python Client Library

A Python client library for getting JWT tokens from SingleStore's IAM service when running in cloud environments (AWS, GCP, Azure).

## Installation

```bash
pip install singlestore-auth-iam
```

## Quick Start

```python
import asyncio
from s2iam import get_jwt_database

async def main():
    # Get a JWT token for database access
    jwt_token = await get_jwt_database("your-workspace-group-id")
    print(f"JWT: {jwt_token}")

    # Or with no workspace group ID (some configurations)
    jwt_token = await get_jwt_database()
    print(f"JWT: {jwt_token}")

if __name__ == "__main__":
    asyncio.run(main())
```

For API gateway access:

```python
import asyncio
from s2iam import get_jwt_api

async def main():
    # Get a JWT token for API gateway access
    jwt_token = await get_jwt_api()
    print(f"JWT: {jwt_token}")

if __name__ == "__main__":
    asyncio.run(main())
```

That's it! The library automatically detects your cloud environment and gets the appropriate JWT token.

## Configuration

### Environment Variables

- `S2IAM_SERVER_URL`: Custom authentication server URL (default: https://auth.singlestore.com)
- `S2IAM_DEBUGGING`: Set to "true" to enable debug logging

## Supported Environments

The library automatically detects and works in:

- **AWS**: EC2 instances, Lambda functions, ECS tasks
- **Google Cloud**: Compute Engine, Cloud Functions, Cloud Run
- **Azure**: Virtual Machines, Functions, Container Instances

## Error Handling

```python
from s2iam import get_jwt_database, NoCloudProviderDetectedError

try:
    jwt_token = await get_jwt_database("workspace-id")
except NoCloudProviderDetectedError:
    print("Not running in a supported cloud environment")
```

## Configuration

### Workspace Group ID

The `workspace_group_id` parameter is optional for `get_jwt_database()`. When provided, it scopes the JWT token to a specific workspace group. When omitted (or `None`), the token may have broader access depending on your SingleStore configuration.

### Environment Variables

- `S2IAM_DEBUGGING`: Set to "true" to enable debug logging
- `S2IAM_SERVER_URL`: Custom authentication server URL (default: https://auth.singlestore.com)

### Provider-Specific Configuration

#### AWS
- Uses standard AWS SDK configuration (AWS_REGION, AWS_PROFILE, etc.)
- Supports IAM roles, EC2 instance profiles, and Lambda execution roles

#### GCP
- Uses Application Default Credentials (ADC)
- Supports service account impersonation via `GCE_METADATA_HOST`

#### Azure
- Uses Azure SDK configuration
- Supports managed identities and service principals

## API Reference

### Core Functions

#### `detect_provider(timeout=5.0, logger=None, clients=None)`

Automatically detect which cloud provider the application is running on.

**Parameters:**
- `timeout` (float): Detection timeout in seconds
- `logger` (Logger): Custom logger instance
- `clients` (List[CloudProviderClient]): Custom list of provider clients

**Returns:** `CloudProviderClient`

#### `get_jwt(jwt_type, workspace_group_id=None, server_url=None, **kwargs)`

Get a JWT token from SingleStore's authentication service.

**Parameters:**
- `jwt_type` (JWTType): Type of JWT to request
- `workspace_group_id` (str): Workspace group ID
- `server_url` (str): Authentication server URL
- `**kwargs`: Additional provider-specific parameters

**Returns:** `str` (JWT token)

### Cloud Provider Clients

All provider clients implement the `CloudProviderClient` interface:

#### Methods

- `detect()`: Test if running on this cloud provider
- `get_type()`: Get the provider type
- `assume_role(role_identifier)`: Assume a different role/identity
- `get_identity_headers(additional_params=None)`: Get authentication headers

### Models

#### `CloudIdentity`

Represents verified identity information:

```python
@dataclass
class CloudIdentity:
    provider: CloudProviderType
    identifier: str
    account_id: str
    region: str
    resource_type: str
    additional_claims: Dict[str, str]
```

#### `CloudProviderType`

Enum of supported cloud providers:
- `AWS`
- `GCP`
- `AZURE`

#### `JWTType`

Enum of JWT types:
- `DATABASE_ACCESS`
- `API_GATEWAY_ACCESS`

## Error Handling

The library defines several specific exceptions:

- `NoCloudProviderDetectedError`: No cloud provider could be detected
- `ProviderNotDetectedError`: Provider not detected, call `detect()` first
- `ProviderDetectedNoIdentityError`: Provider detected but no identity available
- `AssumeRoleNotSupportedError`: Assume role not supported by provider

## Development

### Testing

The library includes comprehensive tests that use the Go test server for integration testing:

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=s2iam --cov-report=html
```

### Code Quality

```bash
# Format code
black src tests
isort src tests

# Lint
flake8 src tests
mypy src
```

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for your changes
5. Run the test suite
6. Submit a pull request

## Support

For issues and questions, please use the [GitHub Issues](https://github.com/singlestore-labs/singlestore-auth-iam/issues) page.
