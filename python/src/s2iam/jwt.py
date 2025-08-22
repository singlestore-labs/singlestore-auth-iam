"""
JWT functionality for SingleStore authentication.
"""

import asyncio
import os
import socket
import time
from typing import Any, Optional

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
    env_server_url = os.environ.get("S2IAM_JWT_SERVER_URL")
    if server_url is None:
        if env_server_url:
            server_url = env_server_url
        else:
            server_url = DEFAULT_SERVER_URL.format(jwt_type=jwt_type.value)

    # Log request if logger available (aligned with Go: no JSON body sent, identity conveyed via headers only)
    if logger:
        logger.log(
            "Requesting JWT (type="
            f"{jwt_type.value}) from {server_url} provider={identity.provider.value} "
            f"workspace_group_id={workspace_group_id or '<none>'}"
        )

    connector = None
    if os.environ.get("S2IAM_FORCE_IPV4") == "1":  # optional mitigation for IPv6 stalls
        connector = aiohttp.TCPConnector(family=socket.AF_INET)

    start = time.monotonic()

    # Lightweight phase tracing (only adds small overhead). Captures which phase we reached
    # so timeout/connect errors are more actionable without deep instrumentation.
    phase: str = "init"
    phases: list[str] = []

    trace = aiohttp.TraceConfig()

    from aiohttp import ClientSession
    from aiohttp.tracing import (
        TraceConnectionCreateEndParams,
        TraceConnectionCreateStartParams,
        TraceRequestEndParams,
        TraceRequestStartParams,
    )

    @trace.on_request_start.append
    async def _on_request_start(
        session: ClientSession,
        ctx: Any,
        params: TraceRequestStartParams,
    ) -> None:  # type: ignore[unused-ignore]
        nonlocal phase
        phase = "request_start"
        phases.append(phase)

    @trace.on_connection_create_start.append
    async def _on_conn_start(
        session: ClientSession,
        ctx: Any,
        params: TraceConnectionCreateStartParams,
    ) -> None:  # type: ignore[unused-ignore]
        nonlocal phase
        phase = "connect_start"
        phases.append(phase)

    @trace.on_connection_create_end.append
    async def _on_conn_end(
        session: ClientSession,
        ctx: Any,
        params: TraceConnectionCreateEndParams,
    ) -> None:  # type: ignore[unused-ignore]
        nonlocal phase
        phase = "connect_end"
        phases.append(phase)

    @trace.on_request_end.append
    async def _on_request_end(
        session: ClientSession,
        ctx: Any,
        params: TraceRequestEndParams,
    ) -> None:  # type: ignore[unused-ignore]
        nonlocal phase
        phase = "request_end"
        phases.append(phase)

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout),
            connector=connector,
            trace_configs=[trace],
        ) as session:
            async with session.post(
                server_url,
                headers={
                    **headers,
                    "Content-Type": "application/json",
                },
                # No body (parity with Go implementation)
                data=None,
            ) as response:
                elapsed = (time.monotonic() - start) * 1000.0
                if response.status == 200:
                    # Expect JSON with {"jwt": "..."}
                    response_data = await response.json()
                    jwt_value = response_data.get("jwt")
                    if not isinstance(jwt_value, str) or not jwt_value:
                        raise Exception("No JWT in response")
                    if logger and os.environ.get("S2IAM_DEBUGGING") == "true":
                        logger.log(f"JWT obtained in {elapsed:.1f}ms")
                    return jwt_value
                error_text = await response.text()
                raise Exception(
                    "JWT request failed status="
                    f"{response.status} elapsed_ms={elapsed:.1f} phase={phase} body_snip={error_text[:160]!r}"
                )
    except asyncio.TimeoutError:
        raise Exception(
            "JWT request timeout after "
            f"{timeout}s (elapsed_ms={(time.monotonic()-start)*1000.0:.1f} last_phase={phase} phases={phases})"
        )


# Legacy function name for compatibility
async def get_jwt_token(*args: Any, **kwargs: Any) -> str:
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
    **kwargs: Any,
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
    **kwargs: Any,
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
