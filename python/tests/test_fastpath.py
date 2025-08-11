"""
Fast-path detection tests for s2iam library.

These tests verify that environment variable-based fast-path detection
produces the same results as full detection.
"""

import os
from unittest.mock import patch

import pytest

import s2iam
from s2iam import CloudProviderType

from .testhelp import expect_cloud_provider_detected, validate_identity_and_jwt
from .test_server_utils import GoTestServerManager


@pytest.mark.asyncio
class TestFastPathDetection:
    """Test fast-path detection using environment variables."""

    async def test_fastpath_detection(self):
        """Test that fast-path detection produces same results as full detection."""
        # Skip on NO_ROLE hosts since we need working cloud provider detection
        if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE"):
            pytest.skip("test requires working cloud role - skipped on no-role hosts")

        # Skip if not in a cloud environment - this should work on both role and no-role hosts
        normal_provider = await expect_cloud_provider_detected(timeout=10.0)
        provider_type = normal_provider.get_type()

        print(f"Detected provider: {provider_type.value}")

        # Determine what environment variables should enable fast-path detection
        env_vars_to_set = {}

        if provider_type == CloudProviderType.AWS:
            # For AWS, set AWS environment variables that trigger fast-path detection
            env_vars_to_set = {
                "AWS_EXECUTION_ENV": "AWS_EC2",  # Generic indicator we're on AWS
            }

            # Try to get region from existing environment
            region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
            if region:
                env_vars_to_set["AWS_REGION"] = region

        elif provider_type == CloudProviderType.GCP:
            # For GCP, set GCE_METADATA_HOST to trigger fast-path
            env_vars_to_set = {
                "GCE_METADATA_HOST": "metadata.google.internal",
            }

        elif provider_type == CloudProviderType.AZURE:
            # For Azure, set AZURE_ENV to trigger fast-path
            env_vars_to_set = {
                "AZURE_ENV": "AzureCloud",
            }

        else:
            pytest.fail(f"Unknown provider type: {provider_type}")

        # Test fast-path detection with environment variables set
        with patch.dict(os.environ, env_vars_to_set):
            for key, value in env_vars_to_set.items():
                print(f"Set {key}={value} for fast-path detection")

            # Now test fast-path detection
            fastpath_provider = await s2iam.detect_provider(
                timeout=5.0
            )  # Shorter timeout since fast-path should be quick

            # Verify both detections give the same provider type
            assert (
                normal_provider.get_type() == fastpath_provider.get_type()
            ), "Fast-path detection should give same provider type as normal detection"

            print(f"Fast-path detection test passed for {provider_type.value}")
            print(f"Normal detection provider: {normal_provider.get_type().value}")
            print(f"Fast-path detection provider: {fastpath_provider.get_type().value}")

            # Skip header testing on NO_ROLE hosts where get_identity_headers is expected to fail
            if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE"):
                print("Skipping header testing on NO_ROLE host")
                return

            # Test that both providers work equivalently
            await self._test_equivalent_functionality(normal_provider, fastpath_provider)

    async def _test_equivalent_functionality(self, normal_provider, fastpath_provider):
        """Test that both providers produce equivalent results."""
        try:
            # Test identity headers
            (
                normal_headers,
                normal_identity,
            ) = await normal_provider.get_identity_headers()
            (
                fastpath_headers,
                fastpath_identity,
            ) = await fastpath_provider.get_identity_headers()

            # Compare provider types
            assert (
                normal_identity.provider == fastpath_identity.provider
            ), "Both providers should detect same cloud provider type"

            # Compare identifiers
            assert (
                normal_identity.identifier == fastpath_identity.identifier
            ), "Both providers should extract same identity identifier"

            # Compare account IDs
            assert (
                normal_identity.account_id == fastpath_identity.account_id
            ), "Both providers should extract same account ID"

            # Compare regions
            assert normal_identity.region == fastpath_identity.region, "Both providers should extract same region"

            # End-result validation using shared helper (mirrors Go shared happy-path code)
            server = GoTestServerManager(timeout_minutes=1)
            try:
                server.start()
                # Use helper with fast-path provider
                provider_type = normal_provider.get_type()
                audience = "https://authsvc.singlestore.com" if provider_type == CloudProviderType.GCP else None
                _, fast_identity, claims = await validate_identity_and_jwt(
                    fastpath_provider,
                    workspace_group_id="test-workspace",
                    server_url=f"{server.server_url}/auth/iam/database",
                    audience=audience,
                )
                # Cross-check that fast-path identity matches normal detection identity on critical fields
                assert fast_identity.identifier == normal_identity.identifier, "Identifier mismatch"
                assert fast_identity.provider == normal_identity.provider, "Provider type mismatch"
                assert fast_identity.account_id == normal_identity.account_id, "Account ID mismatch"
                assert fast_identity.region == normal_identity.region, "Region mismatch"
                print("✓ Fast-path validation: identity and JWT claims consistent with normal detection")
            finally:
                server.stop()

            print("✓ Fast-path and normal detection produced equivalent results")

        except Exception as e:
            # If this is a no-role error, that's expected
            if "no role" in str(e).lower() or "no identity" in str(e).lower():
                print(f"Identity extraction failed as expected on no-role host: {e}")
                return
            raise
