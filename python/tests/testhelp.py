"""
Test helper functions for s2iam tests.

This module provides helper functions that match the Go testhelp implementation
to ensure consistent test behavior across language implementations.
"""

import os

import pytest

import s2iam

from s2iam.models import CloudProviderClient


async def expect_cloud_provider_detected(timeout: float = 5.0) -> CloudProviderClient:
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

    try:
        provider = await s2iam.detect_provider(timeout=timeout)
        return provider
    except s2iam.CloudProviderNotFound:
        pytest.fail("Cloud provider detection failed - expected to detect provider in test environment")
    except s2iam.CloudProviderDetectedNoIdentity:
        pytest.skip("cloud provider detected no identity")


async def require_cloud_role(timeout: float = 5.0) -> CloudProviderClient:
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
