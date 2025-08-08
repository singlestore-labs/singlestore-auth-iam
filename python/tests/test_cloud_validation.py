"""
Cloud validation tests that run against real cloud provider services.
"""

import os

import pytest

import s2iam
from s2iam import CloudProviderType, JWTType

from .test_server_utils import GoTestServerManager
from .testhelp import expect_cloud_provider_detected, require_cloud_role


@pytest.fixture(scope="session")
def test_server():
    """Fixture to manage the Go test server for the entire test session."""
    server = GoTestServerManager(timeout_minutes=5)  # Auto-shutdown after 5 minutes, random port
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
        # Use helper function that matches Go testhelp.ExpectCloudProviderDetected
        provider = await expect_cloud_provider_detected(timeout=10.0)

        assert provider is not None
        assert provider.get_type() in (
            CloudProviderType.AWS,
            CloudProviderType.GCP,
            CloudProviderType.AZURE,
        )

        print(f"✓ Detected provider: {provider.get_type()}")

        # Test identity headers - but handle no-role environments
        import os

        if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE"):
            # In no-role environments, getting identity headers should fail
            with pytest.raises(s2iam.ProviderIdentityUnavailable):
                headers, identity = await provider.get_identity_headers()
            print(f"✓ Identity headers correctly failed in no-role environment")
        else:
            # In normal environments, identity headers should work
            headers, identity = await provider.get_identity_headers()
            assert headers is not None
            assert identity is not None
            assert identity.provider == provider.get_type()
            assert identity.identifier is not None
            print(f"✓ Identity: {identity.identifier}")

    @pytest.mark.integration
    async def test_jwt_retrieval_with_test_server(self, test_server):
        """Test JWT retrieval using only public convenience functions with the Go test server."""
        # Use require_cloud_role which skips in no-role environments (matches Go requireCloudRole)
        provider = await require_cloud_role(timeout=10.0)

        try:
            # Test database JWT using convenience function
            database_jwt = await s2iam.get_jwt_database(
                workspace_group_id="test-workspace",
                server_url=f"{test_server.server_url}/auth/iam/database",
            )
            assert database_jwt is not None
            assert isinstance(database_jwt, str)
            assert len(database_jwt) > 100
            assert database_jwt.startswith("eyJ")

            # Test API JWT using convenience function
            api_jwt = await s2iam.get_jwt_api(server_url=f"{test_server.server_url}/auth/iam/api")
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
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
            ):
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected - not running in cloud environment")

    @pytest.mark.integration
    async def test_convenience_functions_with_test_server(self, test_server):
        """Test the convenience functions with the test server."""
        from tests.testhelp import require_cloud_role

        # This test requires cloud role - skip if in no-role environment
        await require_cloud_role()

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
            api_jwt = await s2iam.get_jwt_api(server_url=f"{test_server.server_url}/auth/iam/api")

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
            if (
                os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
                or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
                or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
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
        from tests.testhelp import require_cloud_role

        try:
            # This test requires cloud role - skip if in no-role environment
            provider = await require_cloud_role(timeout=10.0)

            if provider.get_type() != CloudProviderType.AWS:
                pytest.skip("Not running on AWS")

            # Test AWS identity
            headers, identity = await provider.get_identity_headers()
            assert identity.provider == CloudProviderType.AWS
            assert identity.account_id is not None
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

            print(f"✓ AWS Account: {identity.account_id}")
            print(f"✓ AWS Region: {identity.region}")
            print(f"✓ JWT: {len(jwt)} chars")

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
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
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
                pytest.fail(
                    "Cloud provider detection failed - expected to detect provider in test environment"
                )
            pytest.skip("No cloud provider detected")


@pytest.mark.asyncio
class TestHappyPath:
    """
    Comprehensive happy path test that matches the Go testHappyPath function.
    This test validates critical security properties including:
    - Client-side vs server-side identity consistency
    - JWT parsing and claims validation
    - Provider-specific format validation
    - Cross-validation between identity and JWT claims
    """

    @pytest.mark.integration
    async def test_happy_path_comprehensive(self, test_server):
        """
        Test the complete happy path with comprehensive validations matching Go implementation.
        This is the most important test - it validates security-critical properties.
        """
        import jwt
        import re
        from tests.testhelp import require_cloud_role

        # This test requires cloud role - skip if in no-role environment
        provider = await require_cloud_role(timeout=10.0)

        # Get client-side identity for comparison
        client_headers, client_identity = await provider.get_identity_headers()
        assert client_identity is not None, "Client identity should not be nil"
        assert client_identity.identifier != "", "Client identifier should not be empty"

        print(f"✓ Client Identity: {client_identity.identifier}")
        print(f"✓ Client Provider: {client_identity.provider.value}")
        print(f"✓ Client Account ID: {client_identity.account_id}")
        print(f"✓ Client Region: {client_identity.region}")

        # Log the headers being sent to the test server
        print(f"✓ Headers being sent to test server:")
        for key, value in client_headers.items():
            if key.lower() in [
                "authorization",
                "x-cloud-provider",
                "x-aws-access-key-id",
            ]:
                # For JWTs (GCP/Azure), decode and show claims
                if key.lower() == "authorization" and value.startswith("Bearer "):
                    jwt_header = value[7:]  # Remove 'Bearer ' prefix
                    try:
                        # Decode without verification to see claims
                        claims = jwt.decode(jwt_header, options={"verify_signature": False})
                        print(f"    {key}: Bearer <JWT with claims: {claims}>")
                    except Exception as e:
                        print(f"    {key}: Bearer <JWT decode failed: {e}>")
                else:
                    print(f"    {key}: {value}")
            else:
                print(f"    {key}: {value}")

        # Get JWT using the test server
        if provider.get_type() == CloudProviderType.GCP:
            # For GCP, use explicit audience to ensure compatibility
            database_jwt = await s2iam.get_jwt_database(
                workspace_group_id="test-workspace",
                server_url=f"{test_server.server_url}/auth/iam/database",
                additional_params={"audience": "https://authsvc.singlestore.com"},
            )
        else:
            database_jwt = await s2iam.get_jwt_database(
                workspace_group_id="test-workspace",
                server_url=f"{test_server.server_url}/auth/iam/database",
            )

        assert database_jwt is not None, "JWT should not be None"
        assert database_jwt != "", "JWT should not be empty"
        assert database_jwt.startswith("eyJ"), "JWT should start with eyJ"

        # Parse and validate JWT claims (without signature verification for test server)
        jwt_claims = jwt.decode(database_jwt, options={"verify_signature": False})
        assert jwt_claims is not None, "JWT claims should not be None"

        # Debug: Print all JWT claims to see what we're actually getting
        print(f"🔍 JWT Claims from server: {jwt_claims}")

        # Verify this is actually from our Go test server
        created_by_test_server = jwt_claims.get("createdByTestServer", False)
        print(f"🔍 JWT createdByTestServer: {created_by_test_server}")
        assert (
            created_by_test_server is True
        ), f"JWT was not created by Go test server! Claims: {jwt_claims}"

        # Verify the JWT sub claim contains the client identifier
        jwt_subject = jwt_claims.get("sub")
        assert jwt_subject is not None, "JWT sub claim should not be None"
        assert jwt_subject != "", "JWT sub claim should not be empty"

        print(f"🔍 Client Identifier: {client_identity.identifier}")
        print(f"🔍 JWT sub claim: {jwt_subject}")

        # CRITICAL: Client identifier should match JWT sub claim
        assert client_identity.identifier == jwt_subject, (
            f"CRITICAL: Client Identifier ({client_identity.identifier}) differs from JWT sub claim ({jwt_subject}). "
            f"The JWT sub claim should match the client identifier! Full JWT claims: {jwt_claims}"
        )

        # Provider-specific format validations matching Go implementation
        provider_type = provider.get_type()

        if provider_type == CloudProviderType.AWS:
            # AWS AccountID should be in ARN format
            aws_arn_pattern = re.compile(r"^arn:aws:.*:.*:.*")
            assert aws_arn_pattern.match(
                jwt_subject
            ), f"AWS AccountID should be in ARN format, got: {jwt_subject}"

        elif provider_type == CloudProviderType.GCP:
            # For GCP: Identifier should be email, AccountID should be numeric, JWT sub should be email
            gcp_email_pattern = re.compile(
                r"^[a-zA-Z0-9\-_]+@[a-zA-Z0-9\-_]+\.iam\.gserviceaccount\.com$"
            )
            gcp_numeric_pattern = re.compile(r"^\d{10,}$")  # At least 10 digits

            # Identifier should be service account email format
            assert gcp_email_pattern.match(
                client_identity.identifier
            ), f"GCP Identifier should be service account email format, got: {client_identity.identifier}"

            # AccountID should be numeric service account ID
            assert gcp_numeric_pattern.match(
                client_identity.account_id
            ), f"GCP AccountID should be numeric service account ID, got: {client_identity.account_id}"

            # JWT sub claim should match the email identifier
            assert client_identity.identifier == jwt_subject, (
                f"GCP JWT sub claim should contain the email identifier, got: {jwt_subject}, "
                f"expected: {client_identity.identifier}"
            )

        elif provider_type == CloudProviderType.AZURE:
            # Azure AccountID should be subscription ID (UUID format)
            azure_uuid_pattern = re.compile(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
            )
            assert azure_uuid_pattern.match(
                jwt_subject
            ), f"Azure AccountID should be subscription ID (UUID format), got: {jwt_subject}"

        else:
            pytest.fail(f"Unknown provider type: {provider_type}")

        # Additional JWT validations
        assert "iat" in jwt_claims, "JWT should have issued at (iat) claim"
        assert "exp" in jwt_claims, "JWT should have expiration (exp) claim"

        # Verify JWT is not expired (basic sanity check)
        import time

        current_time = int(time.time())
        jwt_exp = jwt_claims.get("exp")
        assert (
            jwt_exp > current_time
        ), f"JWT should not be expired (exp: {jwt_exp}, now: {current_time})"

        print(f"✓ Happy path validation successful for {provider_type.value}")
        print(f"  Client identity: {client_identity.identifier}")
        print(f"  Account ID: {client_identity.account_id}")
        print(f"  JWT subject: {jwt_subject}")
        print(f"  JWT expires: {jwt_exp}")
