"""
Cloud validation tests that run against real cloud provider services.
"""

import os

import pytest

import s2iam
from s2iam import CloudProviderType, JWTType

from .test_server_utils import GoTestServerManager


@pytest.fixture(scope="session")
def test_server():
    """Fixture to manage the Go test server for the entire test session."""
    server = GoTestServerManager(port=8081)  # Use different port than integration tests
    try:
        server.start()
        yield server
    finally:
        server.stop()


class TestCloudProviderValidation:
    """Automated cloud provider validation tests."""

    @pytest.mark.integration
    async def test_provider_detection_and_identity(self):
        """Test that we can detect the current cloud provider and get identity."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)
            assert provider is not None
            assert provider.get_type() in [
                CloudProviderType.AWS,
                CloudProviderType.GCP,
                CloudProviderType.AZURE,
            ]

            # Test identity headers
            headers, identity = await provider.get_identity_headers()
            assert headers is not None
            assert identity is not None
            assert identity.provider == provider.get_type()
            assert identity.identifier is not None

            print(f"✓ Detected provider: {provider.get_type()}")
            print(f"✓ Identity: {identity.identifier}")

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER") or os.environ.get(
                "S2IAM_TEST_ASSUME_ROLE"
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected - not running in cloud environment")

    @pytest.mark.integration
    async def test_jwt_retrieval_with_test_server(self, test_server):
        """Test JWT retrieval using only public convenience functions with the Go test server."""
        try:
            # Test database JWT using convenience function
            database_jwt = await s2iam.get_jwt_database(
                workspace_group_id="test-workspace",
                server_url=f"{test_server.server_url}/auth/iam/database"
            )
            assert database_jwt is not None
            assert isinstance(database_jwt, str)
            assert len(database_jwt) > 100
            assert database_jwt.startswith("eyJ")

            # Test API JWT using convenience function
            api_jwt = await s2iam.get_jwt_api(
                server_url=f"{test_server.server_url}/auth/iam/api"
            )
            assert api_jwt is not None
            assert isinstance(api_jwt, str)
            assert len(api_jwt) > 100
            assert api_jwt.startswith("eyJ")

            # Tokens should be different for different types
            assert database_jwt != api_jwt

            print(f"✓ Database JWT length: {len(database_jwt)}")
            print(f"✓ API JWT length: {len(api_jwt)}")
        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER") or os.environ.get(
                "S2IAM_TEST_ASSUME_ROLE"
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected - not running in cloud environment")

    @pytest.mark.integration
    async def test_convenience_functions_with_test_server(self, test_server):
        """Test the convenience functions with the test server."""
        try:
            # Test database convenience function
            database_jwt = await s2iam.get_jwt_database(
                workspace_group_id="test-workspace",
                server_url=f"{test_server.server_url}/auth/iam/database",
            )

            assert database_jwt is not None
            assert isinstance(database_jwt, str)
            assert len(database_jwt) > 100
            assert database_jwt.startswith("eyJ")

            # Test API convenience function
            api_jwt = await s2iam.get_jwt_api(
                server_url=f"{test_server.server_url}/auth/iam/api"
            )

            assert api_jwt is not None
            assert isinstance(api_jwt, str)
            assert len(api_jwt) > 100
            assert api_jwt.startswith("eyJ")

            # Test without workspace_group_id
            api_jwt_no_workspace = await s2iam.get_jwt_api(
                server_url=f"{test_server.server_url}/auth/iam/api"
            )

            assert api_jwt_no_workspace is not None
            assert isinstance(api_jwt_no_workspace, str)

            print(f"✓ Database convenience function: {len(database_jwt)} chars")
            print(f"✓ API convenience function: {len(api_jwt)} chars")

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER") or os.environ.get(
                "S2IAM_TEST_ASSUME_ROLE"
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected - not running in cloud environment")


class TestProviderSpecificValidation:
    """Provider-specific validation tests."""

    @pytest.mark.integration
    @pytest.mark.aws
    async def test_aws_specific_functionality(self, test_server):
        """Test AWS-specific functionality if running on AWS."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)

            if provider.get_type() != CloudProviderType.AWS:
                pytest.skip("Not running on AWS")

            # Test AWS identity
            headers, identity = await provider.get_identity_headers()
            assert identity.provider == CloudProviderType.AWS
            assert identity.account_id is not None
            assert identity.region is not None

            # Test JWT retrieval
            jwt_token = await s2iam.get_jwt(
                jwt_type=JWTType.DATABASE_ACCESS,
                server_url=f"{test_server.server_url}/auth/iam/database",
                provider=provider,
                workspace_group_id="test-workspace",
            )

            assert jwt_token is not None
            assert len(jwt_token) > 100

            print(f"✓ AWS Account: {identity.account_id}")
            print(f"✓ AWS Region: {identity.region}")
            print(f"✓ JWT Token: {len(jwt_token)} chars")

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER") or os.environ.get(
                "S2IAM_TEST_ASSUME_ROLE"
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected")

    @pytest.mark.integration
    @pytest.mark.gcp
    async def test_gcp_specific_functionality(self, test_server):
        """Test GCP-specific functionality if running on GCP."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)

            if provider.get_type() != CloudProviderType.GCP:
                pytest.skip("Not running on GCP")

            # Test GCP identity
            headers, identity = await provider.get_identity_headers()
            assert identity.provider == CloudProviderType.GCP
            assert identity.account_id is not None  # Project ID
            assert identity.region is not None

            # Test JWT retrieval
            jwt_token = await s2iam.get_jwt(
                jwt_type=JWTType.DATABASE_ACCESS,
                server_url=f"{test_server.server_url}/auth/iam/database",
                provider=provider,
                workspace_group_id="test-workspace",
            )

            assert jwt_token is not None
            assert len(jwt_token) > 100

            print(f"✓ GCP Project: {identity.account_id}")
            print(f"✓ GCP Region: {identity.region}")
            print(f"✓ JWT Token: {len(jwt_token)} chars")

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER") or os.environ.get(
                "S2IAM_TEST_ASSUME_ROLE"
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected")

    @pytest.mark.integration
    @pytest.mark.azure
    async def test_azure_specific_functionality(self, test_server):
        """Test Azure-specific functionality if running on Azure."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)

            if provider.get_type() != CloudProviderType.AZURE:
                pytest.skip("Not running on Azure")

            # Test Azure identity
            headers, identity = await provider.get_identity_headers()
            assert identity.provider == CloudProviderType.AZURE
            assert identity.account_id is not None  # Subscription ID
            assert identity.region is not None

            # Test JWT retrieval
            jwt_token = await s2iam.get_jwt(
                jwt_type=JWTType.DATABASE_ACCESS,
                server_url=f"{test_server.server_url}/auth/iam/database",
                provider=provider,
                workspace_group_id="test-workspace",
            )

            assert jwt_token is not None
            assert len(jwt_token) > 100

            print(f"✓ Azure Subscription: {identity.account_id}")
            print(f"✓ Azure Region: {identity.region}")
            print(f"✓ JWT Token: {len(jwt_token)} chars")

        except s2iam.CloudProviderNotFound:
            # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip (test environment should be configured)
            if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER") or os.environ.get(
                "S2IAM_TEST_ASSUME_ROLE"
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
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
            pytest.skip(
                "Running in cloud environment - cannot test no-provider scenario"
            )
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
            if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER") or os.environ.get(
                "S2IAM_TEST_ASSUME_ROLE"
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected")
