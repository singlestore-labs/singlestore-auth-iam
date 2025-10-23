"""
Test helper functions for s2iam tests.

This module provides helper functions that match the Go testhelp implementation
to ensure consistent test behavior across language implementations.
"""

import base64
import json
import os
from typing import Any, Dict, Optional, Tuple

import pytest

import s2iam
from s2iam.api import DETECT_PROVIDER_DEFAULT_TIMEOUT
from s2iam.models import CloudProviderClient

TEST_DETECT_TIMEOUT = DETECT_PROVIDER_DEFAULT_TIMEOUT  # mirror library default


async def expect_cloud_provider_detected(timeout: float = TEST_DETECT_TIMEOUT) -> CloudProviderClient:
    """
    Detect cloud provider and skip test if none found.
    If S2IAM_TEST_CLOUD_PROVIDER, S2IAM_TEST_ASSUME_ROLE, or S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE is set,
    fail instead of skip (test environment should be configured).

    This matches the Go testhelp.ExpectCloudProviderDetected function.
    """
    # Check if we're in a test environment where cloud provider should be detected
    if not (
        os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
        or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
        or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
    ):
        pytest.skip("cloud provider required")

    # Single attempt only (fail-fast). Retries can mask genuine negative signals
    # (wrong environment / firewall) and slow CI.
    try:
        return await s2iam.detect_provider(timeout=timeout)
    except s2iam.CloudProviderNotFound:
        pytest.fail("Cloud provider detection failed - expected to detect provider in test environment")
    except s2iam.ProviderIdentityUnavailable:
        pytest.skip("cloud provider detected no identity")


async def require_cloud_role(timeout: float = TEST_DETECT_TIMEOUT) -> CloudProviderClient:
    """
    Require cloud provider with working role/identity (not just detection).
    This is for tests that need to actually use the cloud identity, not just detect the provider.

    This matches the Go testhelp.RequireCloudRole function.
    """
    # Skip if we're explicitly in a no-role environment
    if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE"):
        pytest.skip("cloud role required")

    # Use expect_cloud_provider_detected for the actual detection logic
    return await expect_cloud_provider_detected(timeout)


def maybe_parallel() -> None:
    """
    Call pytest.mark.skip for Azure tests in cloud environments to avoid rate limiting.

    Azure has rate limiting issues that cause HTTP 429 errors when tests run in parallel.
    This helper checks cloud test environment variables to determine if we should
    avoid parallel execution.

    Note: pytest doesn't have the same t.Parallel() concept as Go, but this function
    serves as documentation and could be used with pytest-xdist if needed.
    """
    # Check if we're running in any cloud test environment
    cloud_provider = os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
    no_role_provider = os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")

    # If we're testing Azure in any cloud configuration, log a warning
    # (pytest handles parallelization differently than Go's t.Parallel())
    if cloud_provider == "azure" or no_role_provider == "azure":
        # In pytest, we might need to be careful with Azure rate limiting
        # This could be expanded if using pytest-xdist
        pass


async def validate_identity_and_jwt(
    provider: CloudProviderClient,
    workspace_group_id: str,
    server_url: str,
    audience: Optional[str] = None,
) -> Tuple[dict, s2iam.CloudIdentity, dict]:
    """Shared validation: fetch identity headers, request JWT, verify claims vs identity.

    Mirrors Go testHappyPath logic focusing on end-result consistency rather than implementation details.
    Returns (headers, identity, jwt_claims) for further provider-specific assertions.
    """
    # Get identity headers first
    additional_params = {"audience": audience} if audience else None
    headers, identity = await provider.get_identity_headers(additional_params)

    # Request JWT via convenience function (database JWT selected for richer validation)
    token = await s2iam.get_jwt_database(
        workspace_group_id=workspace_group_id,
        server_url=server_url,
        provider=provider,
        additional_params=additional_params,
    )
    assert token and token.count(".") == 2, "JWT structure invalid"

    # Decode payload (test server signature not verified here)
    parts = token.split(".")
    payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
    try:
        claims: Dict[str, Any] = json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception as e:  # pragma: no cover - defensive
        raise AssertionError(f"Failed to decode JWT claims: {e}")

    # Build a synthetic identity from claims for full-struct style comparison like Go test.
    claim_identity = {
        "identifier": claims.get("sub", ""),
        "account_id": claims.get("accountID", ""),
        "region": claims.get("region", ""),
        "provider": str(claims.get("provider", "")),
        "resource_type": claims.get("resourceType", ""),
    }

    # Core identifier must match.
    if claim_identity["identifier"] != identity.identifier:
        raise AssertionError(
            f"JWT sub mismatch: claim={claim_identity['identifier']!r} identity={identity.identifier!r}"
        )

    # Provider must match (case-insensitive).
    if claim_identity["provider"].lower() != identity.provider.value.lower():
        raise AssertionError(
            f"JWT provider mismatch: claim={claim_identity['provider']!r} identity={identity.provider.value!r}"
        )

    # AccountID comparison only when both sides non-empty (avoid false negatives for providers without accountID).
    if identity.account_id and claim_identity["account_id"]:
        if claim_identity["account_id"] != identity.account_id:
            raise AssertionError(
                f"JWT accountID mismatch: claim={claim_identity['account_id']!r} identity={identity.account_id!r}"
            )

    # Region strict equality: if identity has a region we expect claim present and equal.
    if identity.region:
        if claim_identity["region"] != identity.region:
            raise AssertionError(
                f"JWT region mismatch: claim={claim_identity['region']!r} identity={identity.region!r}"
            )
    else:
        # If identity has no region, tolerate empty claim (but avoid surprising non-empty claim differing).
        if claim_identity["region"] and claim_identity["region"] != identity.region:
            raise AssertionError(
                f"JWT region unexpected value when identity has none: claim={claim_identity['region']!r}"
            )

    # resourceType intentionally not asserted strictly (server normalization differences allowed).

    return headers, identity, claims
