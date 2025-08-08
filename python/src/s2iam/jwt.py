"""
JWT functionality for SingleStore authentication.
"""

from typing import Optional

import aiohttp

from .models import (
    CloudProviderClient,
    JWTType,
    Logger,
)

DEFAULT_SERVER_URL = "https://authsvc.singlestore.com/auth/iam/{jwt_type}"


async def get_jwt(
    jwt_type: JWTType,
    workspace_group_id: Optional[str] = None,
    server_url: Optional[str] = None,
    provider: Optional[CloudProviderClient] = None,
    additional_params: Optional[dict[str, str]] = None,
    assume_role_identifier: Optional[str] = None,
    timeout: float = 10.0,
    logger: Optional[Logger] = None,
    **kwargs,
) -> str:
    """
    Get a JWT from SingleStore's authentication service.

    This function attempts to obtain a JWT from SingleStore's authentication service
    using the detected cloud provider's identity.

    Args:
        jwt_type (JWTType): The type of JWT to request (database, api)
        workspace_group_id (Optional[str]): Workspace group ID to scope the JWT to.
            Only used for database JWTs. When None, the JWT may have broader access.
        timeout (float): Timeout in seconds for the request
        server_url (Optional[str]): Override the default server URL
        logger (Optional[Logger]): Logger instance for debug output

    Returns:
        str: JWT string

    Raises:
        NoCloudProviderDetectedError: If no cloud provider is detected
        Exception: If JWT acquisition fails
    """
    # Detect provider if not provided
    if provider is None:
        # Import here to avoid circular import
        from .api import detect_provider

        provider = await detect_provider(logger=logger, **kwargs)

    # Assume role if requested
    if assume_role_identifier:
        provider = provider.assume_role(assume_role_identifier)

    # Get identity headers
    headers, identity = await provider.get_identity_headers(additional_params)

    # Prepare server URL, allow override via environment variable
    import os

    env_server_url = os.environ.get("S2IAM_JWT_SERVER_URL")
    if server_url is None:
        if env_server_url:
            server_url = env_server_url
        else:
            server_url = DEFAULT_SERVER_URL.format(jwt_type=jwt_type.value)

    # Prepare request body
    request_data = {
        "provider": identity.provider.value,
        "identity": {
            "identifier": identity.identifier,
            "account_id": identity.account_id,
            "region": identity.region,
            "resource_type": identity.resource_type,
            "additional_claims": identity.additional_claims,
        },
    }

    if workspace_group_id:
        request_data["workspace_group_id"] = workspace_group_id

    # Log request if logger available
    if logger:
        logger.log(
            f"Requesting JWT from {server_url} for provider {identity.provider.value}"
        )

    # Make JWT request
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=timeout)
    ) as session:
        async with session.post(
            server_url,
            headers={
                **headers,
                "Content-Type": "application/json",
            },
            json=request_data,
        ) as response:
            if response.status == 200:
                response_data = await response.json()
                jwt = response_data.get("jwt")
                if not jwt:
                    raise Exception("No JWT in response")

                if logger:
                    logger.log("Successfully obtained JWT")

                return jwt
            else:
                error_text = await response.text()
                raise Exception(
                    f"JWT request failed with status {response.status}: {error_text}"
                )


# Legacy function name for compatibility
async def get_jwt_token(*args, **kwargs) -> str:
    """Legacy alias for get_jwt."""
    return await get_jwt(*args, **kwargs)


# Convenience functions for specific JWT types
async def get_jwt_database(
    workspace_group_id: Optional[str] = None,
    server_url: str = "https://authsvc.singlestore.com/auth/iam/database",
    provider: Optional[CloudProviderClient] = None,
    additional_params: Optional[dict[str, str]] = None,
    assume_role_identifier: Optional[str] = None,
    timeout: float = 10.0,
    logger: Optional[Logger] = None,
    **kwargs,
) -> str:
    """
    Get a JWT for database access.

    Args:
        workspace_group_id: Workspace group ID (optional - can be None or empty string)
        server_url: Authentication server URL (defaults to production)
        provider: Optional provider client (will auto-detect if not provided)
        additional_params: Additional provider-specific parameters
        assume_role_identifier: Role to assume before getting JWT
        timeout: Request timeout in seconds
        logger: Optional logger instance
        **kwargs: Additional options

    Returns:
        str: JWT string for database access
    """
    return await get_jwt(
        jwt_type=JWTType.DATABASE_ACCESS,
        workspace_group_id=workspace_group_id,
        server_url=server_url,
        provider=provider,
        additional_params=additional_params,
        assume_role_identifier=assume_role_identifier,
        timeout=timeout,
        logger=logger,
        **kwargs,
    )


async def get_jwt_api(
    workspace_group_id: Optional[str] = None,
    server_url: str = "https://authsvc.singlestore.com/auth/iam/api",
    provider: Optional[CloudProviderClient] = None,
    additional_params: Optional[dict[str, str]] = None,
    assume_role_identifier: Optional[str] = None,
    timeout: float = 10.0,
    logger: Optional[Logger] = None,
    **kwargs,
) -> str:
    """
    Get a JWT for API gateway access.

    Args:
        server_url: Authentication server URL (defaults to production)
        provider: Optional provider client (will auto-detect if not provided)
        additional_params: Additional provider-specific parameters
        assume_role_identifier: Role to assume before getting JWT
        timeout: Request timeout in seconds
        logger: Optional logger instance
        **kwargs: Additional options

    Returns:
        str: JWT string for API gateway access
    """
    return await get_jwt(
        jwt_type=JWTType.API_GATEWAY_ACCESS,
        workspace_group_id=workspace_group_id,
        server_url=server_url,
        provider=provider,
        additional_params=additional_params,
        assume_role_identifier=assume_role_identifier,
        timeout=timeout,
        logger=logger,
        **kwargs,
    )
