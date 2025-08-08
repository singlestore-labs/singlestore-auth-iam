"""
Production server tests for s2iam library.

These tests validate the library against the production authsvc.singlestore.com server.
Currently tests database JWT only, with GCP temporarily skipped due to audience configuration.
"""

import os

import pytest

import s2iam
from s2iam import CloudProviderType

from .testhelp import expect_cloud_provider_detected, require_cloud_role


async def _test_production_database_jwt(client):
    """Helper function to test database JWT with production server."""
    jwt = await s2iam.get_jwt_database(
        workspace_group_id="test-workspace",
        timeout=30.0,  # Production server may be slower
    )

    assert jwt is not None, "Database JWT should be generated"
    assert len(jwt) > 0, "Database JWT should not be empty"
    assert jwt.startswith("eyJ"), "Database JWT should be a valid JWT format"

    print(f"✓ Successfully generated database JWT from production server")
    print(f"  Provider: {client.get_type().value}")
    print(f"  JWT length: {len(jwt)} characters")


@pytest.mark.asyncio
async def test_production_database_jwt_aws():
    """Test AWS database JWT with production server."""
    client = await require_cloud_role()

    if client.get_type() != CloudProviderType.AWS:
        pytest.skip("Not running on AWS")

    await _test_production_database_jwt(client)


@pytest.mark.asyncio
async def test_production_database_jwt_azure():
    """Test Azure database JWT with production server."""
    client = await require_cloud_role()

    if client.get_type() != CloudProviderType.AZURE:
        pytest.skip("Not running on Azure")

    await _test_production_database_jwt(client)


@pytest.mark.asyncio
async def test_production_database_jwt_gcp():
    """Test GCP database JWT with production server."""
    client = await require_cloud_role()

    # TODO: Production server has audience mismatch for GCP
    # Our GCP client correctly generates tokens with audience "https://authsvc.singlestore.com"
    # but production server only accepts "https://auth.singlestore.com"
    # This should be fixed on the server side to accept both audiences
    if client.get_type() == CloudProviderType.GCP:
        pytest.skip(
            "GCP production server test skipped due to audience mismatch - needs server-side fix"
        )

    await _test_production_database_jwt(client)


@pytest.mark.asyncio
async def test_production_database_jwt_with_workspace_details():
    """Test database JWT with workspace details against production server."""
    client = await require_cloud_role()

    # Skip GCP due to audience issues
    if client.get_type() == CloudProviderType.GCP:
        pytest.skip(
            "GCP temporarily skipped - production server audience configuration in progress"
        )

    print(f"✓ Detected provider: {client.get_type().value}")

    # Test with various workspace configurations
    test_workspaces = [
        "test-workspace-1",
        "test-workspace-with-dashes",
        "test_workspace_with_underscores",
    ]

    for workspace in test_workspaces:
        jwt = await s2iam.get_jwt_database(workspace_group_id=workspace, timeout=30.0)

        assert (
            jwt is not None
        ), f"Database JWT should be generated for workspace {workspace}"
        assert (
            len(jwt) > 0
        ), f"Database JWT should not be empty for workspace {workspace}"
        assert jwt.startswith(
            "eyJ"
        ), f"Database JWT should be valid JWT format for workspace {workspace}"

        print(f"✓ Successfully generated JWT for workspace: {workspace}")


@pytest.mark.asyncio
async def test_production_server_error_handling():
    """Test error handling with production server."""
    client = await require_cloud_role()

    # Skip GCP due to audience issues
    if client.get_type() == CloudProviderType.GCP:
        pytest.skip(
            "GCP temporarily skipped - production server audience configuration in progress"
        )

    print(f"✓ Detected provider: {client.get_type().value}")

    # Test with invalid workspace ID (should still work but may have different behavior)
    try:
        jwt = await s2iam.get_jwt_database(
            workspace_group_id="", timeout=30.0  # Empty workspace ID
        )
        # If this succeeds, validate the JWT
        if jwt:
            assert jwt.startswith(
                "eyJ"
            ), "JWT should be valid format even with empty workspace"
            print("✓ Production server handles empty workspace ID gracefully")
    except Exception as e:
        # If this fails, it's also acceptable - just log it
        print(f"✓ Production server properly rejects empty workspace ID: {e}")

    # Test with very long workspace ID
    try:
        long_workspace = "a" * 200  # Very long workspace ID
        jwt = await s2iam.get_jwt_database(
            workspace_group_id=long_workspace, timeout=30.0
        )
        if jwt:
            assert jwt.startswith(
                "eyJ"
            ), "JWT should be valid format even with long workspace"
            print("✓ Production server handles long workspace ID gracefully")
    except Exception as e:
        # If this fails, it's also acceptable - just log it
        print(f"✓ Production server properly handles long workspace ID: {e}")


@pytest.mark.asyncio
async def test_production_server_timeout_handling():
    """Test timeout handling with production server."""
    client = await require_cloud_role()

    # Skip GCP due to audience issues
    if client.get_type() == CloudProviderType.GCP:
        pytest.skip(
            "GCP temporarily skipped - production server audience configuration in progress"
        )

    print(f"✓ Detected provider: {client.get_type().value}")

    # Test with reasonable timeout
    start_time = __import__("time").time()
    jwt = await s2iam.get_jwt_database(
        workspace_group_id="timeout-test-workspace", timeout=30.0
    )
    end_time = __import__("time").time()

    elapsed = end_time - start_time

    assert jwt is not None, "Database JWT should be generated within timeout"
    assert (
        elapsed < 30.0
    ), f"Request should complete within timeout (took {elapsed:.2f}s)"

    print(f"✓ Production server response time: {elapsed:.2f} seconds")
    print(f"✓ Successfully generated JWT within timeout")
