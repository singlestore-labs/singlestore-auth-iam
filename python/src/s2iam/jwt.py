"""
JWT functionality for SingleStore authentication.
"""

from typing import Any, Optional

import aiohttp

from .aws import ROLE_SESSION_NAME_PARAM
from .identity_format import (
    FORMAT_AWS_ARN,
    IDENTITY_FORMAT_PREFERENCE_ENV,
    IDENTITY_FORMAT_PREFERENCE_HEADER,
    parse_identity_format_preference,
)
from .models import CloudProviderClient, JWTType, Logger

DEFAULT_SERVER_URL = "https://authsvc.singlestore.com/auth/iam/{jwt_type}"

# Sentinel distinguishing "preference not supplied" (fall back to env/default)
# from an explicit empty preference (send no header).
_PREFERENCE_UNSET = object()


def _resolve_identity_format_preference(preference: Any) -> list[str]:
    """Resolve the effective preference using option > env var > built-in default.

    The built-in default is [aws-arn], byte-identical to the historical behavior:
    GCP/Azure tokens are absent, so those providers fall through to the verifier's
    default ordering (also unchanged).
    """
    if preference is not _PREFERENCE_UNSET and preference is not None:
        return list(preference)
    import os

    env = os.environ.get(IDENTITY_FORMAT_PREFERENCE_ENV)
    if env:
        return parse_identity_format_preference(env)
    return [FORMAT_AWS_ARN]


async def get_jwt(
    jwt_type: JWTType,
    workspace_group_id: Optional[str] = None,
    server_url: Optional[str] = None,
    allow_http: bool = False,
    provider: Optional[CloudProviderClient] = None,
    additional_params: Optional[dict[str, str]] = None,
    assume_role_identifier: Optional[str] = None,
    assume_role_session_name: Optional[str] = None,
    identity_format_preference: Any = _PREFERENCE_UNSET,
    timeout: float = 10.0,
    logger: Optional[Logger] = None,
    **kwargs: Any,
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
        allow_http (bool): Permit http:// server URLs (for local testing only; default False)
        logger (Optional[Logger]): Logger instance for debug output

    Returns:
        str: JWT string

    Raises:
        NoCloudProviderDetectedError: If no cloud provider is detected
        Exception: If JWT acquisition fails
    """
    import os

    env_server_url = os.environ.get("S2IAM_JWT_SERVER_URL")
    if server_url is None:
        if env_server_url:
            server_url = env_server_url
        else:
            server_url = DEFAULT_SERVER_URL.format(jwt_type=jwt_type.value)

    from .https import validate_auth_server_url

    validate_auth_server_url(server_url, allow_http=allow_http)

    # Detect provider if not provided
    if provider is None:
        # Import here to avoid circular import
        from .api import detect_provider

        provider = await detect_provider(logger=logger, **kwargs)

    # Assume role if requested
    if assume_role_identifier:
        provider = provider.assume_role(assume_role_identifier)

    if assume_role_session_name:
        import warnings

        warnings.warn(
            "assume_role_session_name is deprecated and no longer affects the issued "
            "identity: AWS assumed-role sessions map to the base IAM role ARN regardless "
            "of session name. The value is still sent to AWS (visible in CloudTrail).",
            DeprecationWarning,
            stacklevel=2,
        )
        additional_params = dict(additional_params or {})
        additional_params[ROLE_SESSION_NAME_PARAM] = assume_role_session_name

    # Get identity headers
    headers, identity = await provider.get_identity_headers(additional_params)

    # Advertise the client's identity-format preference (content negotiation). The
    # verifier chooses the first supported-and-valid format; older servers ignore
    # this header and keep their default behavior.
    preference = _resolve_identity_format_preference(identity_format_preference)
    if preference:
        headers = {**headers, IDENTITY_FORMAT_PREFERENCE_HEADER: ",".join(preference)}

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
        logger.log(f"Requesting JWT from {server_url} for provider {identity.provider.value}")

    # Make JWT request
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
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
                jwt_value = response_data.get("jwt")
                if not isinstance(jwt_value, str) or not jwt_value:
                    raise Exception("No JWT in response")

                if logger:
                    logger.log("Successfully obtained JWT")

                return jwt_value
            else:
                error_text = await response.text()
                raise Exception(f"JWT request failed with status {response.status}: {error_text}")


# Single canonical JWT API: get_jwt (+ convenience wrappers below).


# Convenience functions for specific JWT types
async def get_jwt_database(
    workspace_group_id: Optional[str] = None,
    server_url: str = "https://authsvc.singlestore.com/auth/iam/database",
    allow_http: bool = False,
    provider: Optional[CloudProviderClient] = None,
    additional_params: Optional[dict[str, str]] = None,
    assume_role_identifier: Optional[str] = None,
    assume_role_session_name: Optional[str] = None,
    identity_format_preference: Any = _PREFERENCE_UNSET,
    timeout: float = 10.0,
    logger: Optional[Logger] = None,
    **kwargs: Any,
) -> str:
    """
    Get a JWT for database access.

    Args:
        workspace_group_id: Workspace group ID (optional - can be None or empty string)
        server_url: Authentication server URL (defaults to production)
        allow_http: Permit http:// server URLs (for local testing only; default False)
        provider: Optional provider client (will auto-detect if not provided)
        additional_params: Additional provider-specific parameters
        assume_role_identifier: Role to assume before getting JWT
        assume_role_session_name: Deprecated. AWS STS RoleSessionName when assuming a
            role. No longer affects the issued identity (assumed-role sessions map to
            the base IAM role ARN); still sent to AWS for CloudTrail visibility.
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
        allow_http=allow_http,
        provider=provider,
        additional_params=additional_params,
        assume_role_identifier=assume_role_identifier,
        assume_role_session_name=assume_role_session_name,
        identity_format_preference=identity_format_preference,
        timeout=timeout,
        logger=logger,
        **kwargs,
    )


async def get_jwt_api(
    workspace_group_id: Optional[str] = None,
    server_url: str = "https://authsvc.singlestore.com/auth/iam/api",
    allow_http: bool = False,
    provider: Optional[CloudProviderClient] = None,
    additional_params: Optional[dict[str, str]] = None,
    assume_role_identifier: Optional[str] = None,
    assume_role_session_name: Optional[str] = None,
    identity_format_preference: Any = _PREFERENCE_UNSET,
    timeout: float = 10.0,
    logger: Optional[Logger] = None,
    **kwargs: Any,
) -> str:
    """
    Get a JWT for API gateway access.

    Args:
        server_url: Authentication server URL (defaults to production)
        allow_http: Permit http:// server URLs (for local testing only; default False)
        provider: Optional provider client (will auto-detect if not provided)
        additional_params: Additional provider-specific parameters
        assume_role_identifier: Role to assume before getting JWT
        assume_role_session_name: Deprecated. AWS STS RoleSessionName when assuming a
            role. No longer affects the issued identity (assumed-role sessions map to
            the base IAM role ARN); still sent to AWS for CloudTrail visibility.
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
        allow_http=allow_http,
        provider=provider,
        additional_params=additional_params,
        assume_role_identifier=assume_role_identifier,
        assume_role_session_name=assume_role_session_name,
        identity_format_preference=identity_format_preference,
        timeout=timeout,
        logger=logger,
        **kwargs,
    )
