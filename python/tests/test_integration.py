"""
Integration tests for s2iam library.

These tests require a real cloud environment and the Go test server.
"""

import os

import pytest

import s2iam
from s2iam import CloudProviderType, JWTType

from .test_server_utils import GoTestServerManager
from .testhelp import expect_cloud_provider_detected, require_cloud_role


@pytest.fixture(scope="session")
def test_server():
    """Fixture to manage the test server lifecycle."""
    server = GoTestServerManager(
        timeout_minutes=5
    )  # Auto-shutdown after 5 minutes, random port
    server.start()
    yield server
    server.stop()


@pytest.mark.asyncio
class TestCloudProviderDetection:
    """Test cloud provider detection in real environments."""

    async def test_detect_provider_success(self):
        """Test that provider detection works in a cloud environment."""
        # Use helper function that matches Go testhelp.ExpectCloudProviderDetected
        provider = await expect_cloud_provider_detected(timeout=10.0)

        assert provider is not None
        assert provider.get_type() in [
            CloudProviderType.AWS,
            CloudProviderType.GCP,
            CloudProviderType.AZURE,
        ]
        print(f"Detected provider: {provider.get_type().value}")

    async def test_get_identity_headers(self):
        """Test getting identity headers from detected provider."""
        from tests.testhelp import require_cloud_role

        try:
            # This test requires cloud role - skip if in no-role environment
            provider = await require_cloud_role(timeout=10.0)
            headers, identity = await provider.get_identity_headers()

            assert headers is not None
            assert identity is not None
            assert identity.provider == provider.get_type()
            assert identity.identifier != ""

            # Check for provider-specific headers
            if provider.get_type() == s2iam.CloudProviderType.AWS:
                assert "X-AWS-Access-Key-ID" in headers
                assert "X-AWS-Secret-Access-Key" in headers
                assert "X-Cloud-Provider" in headers
            else:
                # GCP and Azure use Authorization header
                assert "Authorization" in headers

            print(f"Identity: {identity.identifier}")
            print(f"Account ID: {identity.account_id}")
            print(f"Region: {identity.region}")

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip(
                "No cloud provider detected - not running in a cloud environment"
            )


@pytest.mark.asyncio
class TestJWTIntegration:
    """Test JWT functionality with the Go test server."""

    async def test_jwt_request_with_test_server(self, test_server):
        """Test JWT request against the Go test server."""
        try:
            # Use helper function that requires working cloud role
            provider = await require_cloud_role(timeout=10.0)

            # Get JWT using test server
            jwt = await s2iam.get_jwt(
                jwt_type=JWTType.DATABASE_ACCESS,
                server_url=f"{test_server.server_url}/auth/iam/database",
                provider=provider,
                workspace_group_id="test-workspace",
            )

            assert jwt is not None
            assert isinstance(jwt, str)
            assert len(jwt) > 0

            print(f"Received JWT: {jwt[:50]}...")

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip(
                "No cloud provider detected - not running in a cloud environment"
            )

    async def test_jwt_different_types(self, test_server):
        """Test different JWT types with the test server."""
        from tests.testhelp import require_cloud_role

        try:
            # This test requires cloud role - skip if in no-role environment
            provider = await require_cloud_role(timeout=10.0)

            for jwt_type in [JWTType.DATABASE_ACCESS, JWTType.API_GATEWAY_ACCESS]:
                jwt = await s2iam.get_jwt(
                    jwt_type=jwt_type,
                    server_url=f"{test_server.server_url}/auth/iam/{jwt_type.value}",
                    provider=provider,
                    workspace_group_id="test-workspace",
                )

                assert jwt is not None
                print(f"JWT for {jwt_type.value}: {jwt[:50]}...")

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip(
                "No cloud provider detected - not running in a cloud environment"
            )


@pytest.mark.asyncio
class TestProviderSpecific:
    """Test provider-specific functionality."""

    async def test_aws_assume_role(self):
        """Test AWS role assumption if running on AWS."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)

            if provider.get_type() != CloudProviderType.AWS:
                pytest.skip("Not running on AWS")

            # Test assume role (this will fail without proper role setup, but tests the interface)
            test_role_arn = "arn:aws:iam::123456789012:role/TestRole"
            assumed_provider = provider.assume_role(test_role_arn)

            assert assumed_provider is not None
            assert assumed_provider.get_type() == CloudProviderType.AWS
            assert assumed_provider != provider  # Should be a different instance

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected")

    async def test_gcp_service_account_impersonation(self):
        """Test GCP service account impersonation if running on GCP."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)

            if provider.get_type() != CloudProviderType.GCP:
                pytest.skip("Not running on GCP")

            # Test service account impersonation interface
            test_sa_email = "test@test-project.iam.gserviceaccount.com"
            impersonated_provider = provider.assume_role(test_sa_email)

            assert impersonated_provider is not None
            assert impersonated_provider.get_type() == CloudProviderType.GCP
            assert impersonated_provider != provider

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected")

    async def test_azure_managed_identity(self):
        """Test Azure managed identity if running on Azure."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)

            if provider.get_type() != CloudProviderType.AZURE:
                pytest.skip("Not running on Azure")

            # Test managed identity interface
            test_identity_id = "test-managed-identity"
            mi_provider = provider.assume_role(test_identity_id)

            assert mi_provider is not None
            assert mi_provider.get_type() == CloudProviderType.AZURE
            assert mi_provider != provider

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected")


@pytest.mark.asyncio
class TestErrorHandling:
    """Test error handling and edge cases."""

    async def test_no_provider_detected_outside_cloud(self):
        """Test behavior when not running in a cloud environment."""
        # This test might pass or fail depending on where it's run
        # If run locally (not in cloud), should raise CloudProviderNotFound
        # If run in cloud, should succeed
        pass  # Behavior depends on environment

    async def test_invalid_jwt_server_url(self):
        """Test handling of invalid JWT server URLs."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)

            with pytest.raises(Exception):  # Should raise some kind of network error
                await s2iam.get_jwt(
                    jwt_type=JWTType.DATABASE_ACCESS,
                    server_url="http://invalid-server:9999/auth",
                    provider=provider,
                    workspace_group_id="test",
                )

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected")

    async def test_provider_not_detected_error(self):
        """Test ProviderNotDetected when using undetected provider."""
        from s2iam.aws import AWSClient

        # Create a new client that hasn't been detected
        client = AWSClient()

        with pytest.raises(s2iam.ProviderNotDetected):
            await client.get_identity_headers()


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])
