"""Cloud validation tests that run against real cloud provider services."""

import json
import os
import re
import time

import pytest

import s2iam
from s2iam import CloudProviderType, JWTType

from .test_server_utils import get_shared_server
from .testhelp import expect_cloud_provider_detected, require_cloud_role, validate_identity_and_jwt


@pytest.fixture(scope="session")
def test_server():
    return get_shared_server()


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
                allow_http=True,
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
                allow_http=True,
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
                    allow_http=True,
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


@pytest.mark.asyncio
class TestAssumeRole:
    """AWS assume-role integration tests (mirrors Go TestGetDatabaseJWT_AssumeRole_Valid)."""

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "session_name",
        [
            pytest.param(None, id="without custom session name"),
            pytest.param("s2iam-test-session", id="with custom session name"),
        ],
    )
    async def test_assume_role_database_jwt(self, test_server, session_name):
        role = os.environ.get("S2IAM_TEST_ASSUME_ROLE")
        if not role:
            pytest.skip("test requires S2IAM_TEST_ASSUME_ROLE environment variable to be set")

        await require_cloud_role(timeout=10.0)

        server_url = f"{test_server.server_url}/auth/iam/database"
        original_jwt = await s2iam.get_jwt_database(
            workspace_group_id="test-workspace",
            server_url=server_url,
            allow_http=True,
        )
        original_claims = _decode_jwt_payload(original_jwt)
        original_identifier = original_claims.get("sub", "")

        kwargs = {
            "workspace_group_id": "test-workspace",
            "server_url": server_url,
            "allow_http": True,
            "assume_role_identifier": role,
        }
        if session_name:
            kwargs["assume_role_session_name"] = session_name

        assumed_jwt = await s2iam.get_jwt_database(**kwargs)
        assumed_claims = _decode_jwt_payload(assumed_jwt)
        assumed_identifier = assumed_claims.get("sub", "")

        assert assumed_identifier != original_identifier, "identity should change when assuming role"
        role_name = role.rsplit("/", 1)[-1] if "/" in role else role
        assert role_name in assumed_identifier, "assumed identity should contain role name"
        if role.startswith("arn:aws:iam:"):
            from s2iam.aws import DEFAULT_ROLE_SESSION_NAME

            expected_session = session_name or DEFAULT_ROLE_SESSION_NAME
            expected_segment = f":assumed-role/{role_name}/{expected_session}"
            assert expected_segment in assumed_identifier, (
                f"assumed identity ARN should contain {expected_segment!r}, got {assumed_identifier!r}"
            )
            assert assumed_identifier.endswith(f"/{expected_session}"), (
                f"assumed identity ARN should end with session name /{expected_session!r}, "
                f"got {assumed_identifier!r}"
            )


def _decode_jwt_payload(token: str) -> dict:
    import base64
    import json

    parts = token.split(".")
    assert len(parts) >= 2, "JWT structure invalid"
    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


class TestLocalOnlyFastPathCancelledContext:
    """Local-only tests for IRSA / workload identity fast detection with cancelled context.

    These mirror the Go cancelled-context fast-path tests but are explicitly skipped when
    running in configured cloud test environments. They validate that FastDetect logic
    (env/file only) executes without consulting context cancellation.
    """

    def _is_cloud_test_env(self) -> bool:
        return bool(
            os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
            or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
            or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
        )

    @pytest.mark.asyncio
    async def test_aws_irsa_cancelled_context(self, tmp_path):
        if self._is_cloud_test_env():
            pytest.skip("IRSA cancelled-context fast-path test is local-only")

        # Create dummy token file
        token_file = tmp_path / "irsa-token.txt"
        token_file.write_text("dummy-token")
        os.environ["AWS_WEB_IDENTITY_TOKEN_FILE"] = str(token_file)
        os.environ["AWS_ROLE_ARN"] = "arn:aws:iam::123456789012:role/TestRole"

        from s2iam.aws import new_client as new_aws_client

        aws_client = new_aws_client()
        await aws_client.fast_detect()
        assert aws_client.get_type() == s2iam.CloudProviderType.AWS

    @pytest.mark.asyncio
    async def test_gcp_workload_identity_cancelled_context(self, tmp_path):
        if self._is_cloud_test_env():
            pytest.skip("GCP workload identity cancelled-context test is local-only")

        # external_account credentials file
        creds_file = tmp_path / "gcp-external.json"
        creds_file.write_text(
            json.dumps(
                {
                    "type": "external_account",
                    "audience": (
                        "//iam.googleapis.com/projects/123/locations/global/"
                        "workloadIdentityPools/pool/providers/provider"
                    ),
                }
            )
        )
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(creds_file)

        from s2iam.gcp import new_client as new_gcp_client

        gcp_client = new_gcp_client()
        await gcp_client.fast_detect()
        assert gcp_client.get_type() == s2iam.CloudProviderType.GCP

    @pytest.mark.asyncio
    async def test_azure_workload_identity_cancelled_context(self, tmp_path):
        if self._is_cloud_test_env():
            pytest.skip("Azure workload identity cancelled-context test is local-only")

        token_file = tmp_path / "azure-federated-token.txt"
        token_file.write_text("dummy-azure-token")
        os.environ["AZURE_FEDERATED_TOKEN_FILE"] = str(token_file)
        os.environ["AZURE_CLIENT_ID"] = "00000000-0000-0000-0000-000000000000"
        os.environ["AZURE_TENANT_ID"] = "11111111-1111-1111-1111-111111111111"

        from s2iam.azure import new_client as new_azure_client

        azure_client = new_azure_client()
        await azure_client.fast_detect()
        assert azure_client.get_type() == s2iam.CloudProviderType.AZURE
