"""Cloud validation tests that run against real cloud provider services."""

import os
import re
import time

import pytest

import s2iam
from s2iam import CloudProviderType, JWTType

from .test_server_utils import GoTestServerManager
from .testhelp import expect_cloud_provider_detected, require_cloud_role, validate_identity_and_jwt


@pytest.fixture(scope="session")
def test_server():
    server = GoTestServerManager(timeout_minutes=5)
    try:
        server.start()
        yield server
    finally:
        server.stop()


@pytest.mark.asyncio
class TestCloudProviderValidation:
    """Fast provider detection + identity sanity test used by quick validation script.

    Keeps the original test path: TestCloudProviderValidation::test_provider_detection_and_identity
    so external quick validation scripts (e.g. run_cloud_validation.sh) that invoke it by name continue to work.
    """

    @pytest.mark.integration
    async def test_provider_detection_and_identity(self):
        # Will skip (no env) or fail (env requires) appropriately inside helper
        provider = await expect_cloud_provider_detected(timeout=5.0)
        # Basic assertions
        assert provider is not None
        ptype = provider.get_type()
        assert ptype in [CloudProviderType.AWS, CloudProviderType.GCP, CloudProviderType.AZURE]
        # Try to get identity headers; in no-role hosts this may raise ProviderIdentityUnavailable
        try:
            headers, identity = await provider.get_identity_headers()
            assert identity.identifier
            assert identity.provider == ptype
            # Minimal field presence (some may be empty depending on provider specifics)
            _ = headers  # ensure used
        except s2iam.ProviderIdentityUnavailable:
            # Acceptable for *-no-role scenarios; skip to keep quick validation green
            pytest.skip("cloud provider detected but no identity available (no-role environment)")


@pytest.mark.asyncio
class TestHappyPath:
    """Comprehensive happy path leveraging shared validation helper (mirrors Go testHappyPath)."""

    @pytest.mark.integration
    async def test_happy_path_comprehensive(self, test_server):
        provider = await require_cloud_role(timeout=10.0)
        audience = "https://authsvc.singlestore.com" if provider.get_type() == CloudProviderType.GCP else None
        headers, identity, claims = await validate_identity_and_jwt(
            provider,
            workspace_group_id="test-workspace",
            server_url=f"{test_server.server_url}/auth/iam/database",
            audience=audience,
        )
        provider_type = provider.get_type()
        sub = claims.get("sub", "")
        print(f"✓ Identity: {identity.identifier} (provider={provider_type.value})")
        print(f"✓ Headers: {[k for k in headers.keys()]}")
        print(f"✓ JWT claims keys: {list(claims.keys())}")

        assert claims.get("createdByTestServer") is True, "JWT should have createdByTestServer=true"

        if provider_type == CloudProviderType.AWS:
            assert re.match(r"^arn:aws:.*:.*:.*", sub), f"AWS ARN format expected, got: {sub}"
        elif provider_type == CloudProviderType.GCP:
            assert re.match(r"^[a-zA-Z0-9\-_]+@[a-zA-Z0-9\-_]+\.iam\.gserviceaccount\.com$", identity.identifier)
            assert re.match(r"^\d{10,}$", identity.account_id)
        elif provider_type == CloudProviderType.AZURE:
            assert re.match(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                sub,
            ), f"Azure subscription UUID format expected, got: {sub}"
        else:  # pragma: no cover
            pytest.fail(f"Unknown provider type: {provider_type}")

        assert "iat" in claims and "exp" in claims, "Missing temporal claims"
        now = int(time.time())
        assert claims["exp"] > now, "JWT expired"
        print(
            "✓ Happy path success: "
            f"id={identity.identifier} "
            f"acct={identity.account_id} "
            f"region={identity.region} "
            f"exp={claims.get('exp')}"
        )


@pytest.mark.asyncio
class TestProviderSpecificIntegration:
    """Provider-specific integration tests (GCP/Azure)."""

    @pytest.mark.integration
    @pytest.mark.gcp
    async def test_gcp_specific_functionality(self, test_server):
        """Test GCP-specific functionality if running on GCP."""
        from tests.testhelp import require_cloud_role

        try:
            # This test requires cloud role - skip if in no-role environment
            provider = await require_cloud_role(timeout=10.0)

            if provider.get_type() != CloudProviderType.GCP:
                pytest.skip("Not running on GCP")

            # Test GCP identity
            headers, identity = await provider.get_identity_headers()
            assert identity.provider == CloudProviderType.GCP
            assert identity.account_id is not None  # Project ID
            assert identity.region is not None

            # Test JWT retrieval
            jwt = await s2iam.get_jwt(
                jwt_type=JWTType.DATABASE_ACCESS,
                server_url=f"{test_server.server_url}/auth/iam/database",
                provider=provider,
                workspace_group_id="test-workspace",
            )

            assert jwt is not None
            assert len(jwt) > 100

            print(f"✓ GCP Project: {identity.account_id}")
            print(f"✓ GCP Region: {identity.region}")
            print(f"✓ JWT: {len(jwt)} chars")

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
            ):
                pytest.fail("Cloud provider detection failed - expected to detect provider in test environment")
            pytest.skip("No cloud provider detected")

    @pytest.mark.integration
    @pytest.mark.azure
    async def test_azure_specific_functionality(self, test_server):
        """Test Azure-specific functionality if running on Azure."""
        from tests.testhelp import require_cloud_role

        try:
            # This test requires cloud role - skip if in no-role environment
            provider = await require_cloud_role(timeout=10.0)

            if provider.get_type() != CloudProviderType.AZURE:
                pytest.skip("Not running on Azure")

            # Test Azure identity
            headers, identity = await provider.get_identity_headers()
            assert identity.provider == CloudProviderType.AZURE
            assert identity.account_id is not None  # Subscription ID
            assert identity.region is not None

            # Test JWT retrieval
            jwt = await s2iam.get_jwt(
                jwt_type=JWTType.DATABASE_ACCESS,
                server_url=f"{test_server.server_url}/auth/iam/database",
                provider=provider,
                workspace_group_id="test-workspace",
            )

            assert jwt is not None
            assert len(jwt) > 100

            print(f"✓ Azure Subscription: {identity.account_id}")
            print(f"✓ Azure Region: {identity.region}")
            print(f"✓ JWT: {len(jwt)} chars")

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
            ):
                pytest.fail("Cloud provider detection failed - expected to detect provider in test environment")
            pytest.skip("No cloud provider detected")


class TestErrorHandlingValidation:
    """Automated error handling validation tests."""

    @pytest.mark.integration
    async def test_no_provider_outside_cloud(self):
        """Test proper error when no cloud provider is detected."""
        # This test is designed to fail gracefully on non-cloud environments
        try:
            provider = await s2iam.detect_provider(timeout=5.0)
            # If we get here, we're in a cloud environment
            assert provider.get_type() in [
                CloudProviderType.AWS,
                CloudProviderType.GCP,
                CloudProviderType.AZURE,
            ]
            pytest.skip("Running in cloud environment - cannot test no-provider scenario")
        except s2iam.CloudProviderNotFound:
            # This is expected when not in cloud
            pass

    @pytest.mark.integration
    async def test_invalid_server_url_handling(self):
        """Test error handling for invalid server URLs."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)

            with pytest.raises(Exception):
                await s2iam.get_jwt(
                    jwt_type=JWTType.DATABASE_ACCESS,
                    server_url="http://invalid-server-url:9999/invalid",
                    provider=provider,
                    timeout=5.0,
                )

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
            ):
                pytest.fail("Cloud provider detection failed - expected to detect provider in test environment")
            pytest.skip("No cloud provider detected")
