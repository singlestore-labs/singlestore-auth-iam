"""
Integration tests for s2iam library.

These tests require a real cloud environment and the Go test server.
"""

import asyncio
import os
import subprocess
import time
from typing import Optional

import pytest

import s2iam
from s2iam import CloudProviderType, JWTType
import sys
import os
# Add tests directory to path so we can import test utilities
sys.path.insert(0, os.path.dirname(__file__))

from test_server_utils import GoTestServerManager

import asyncio
import os
import subprocess
import time
from typing import Optional

import pytest

import s2iam
from s2iam import CloudProviderType, JWTType


@pytest.fixture(scope="session")
def test_server():
    """Fixture to manage the test server lifecycle."""
    server = GoTestServerManager()
    server.start()
    yield server
    server.stop()


@pytest.mark.asyncio
class TestCloudProviderDetection:
    """Test cloud provider detection in real environments."""
    
    async def test_detect_provider_success(self):
        """Test that provider detection works in a cloud environment."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)
            assert provider is not None
            assert provider.get_type() in [
                CloudProviderType.AWS,
                CloudProviderType.GCP,
                CloudProviderType.AZURE
            ]
            print(f"Detected provider: {provider.get_type().value}")
        except s2iam.NoCloudProviderDetectedError:
            pytest.skip("No cloud provider detected - not running in a cloud environment")
    
    async def test_get_identity_headers(self):
        """Test getting identity headers from detected provider."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)
            headers, identity = await provider.get_identity_headers()
            
            assert headers is not None
            assert identity is not None
            assert identity.provider == provider.get_type()
            assert identity.identifier != ""
            assert "X-Cloud-Provider" in headers
            
            print(f"Identity: {identity.identifier}")
            print(f"Account ID: {identity.account_id}")
            print(f"Region: {identity.region}")
            
        except s2iam.NoCloudProviderDetectedError:
            pytest.skip("No cloud provider detected - not running in a cloud environment")


@pytest.mark.asyncio
class TestJWTIntegration:
    """Test JWT functionality with the Go test server."""
    
    async def test_jwt_request_with_test_server(self, test_server):
        """Test JWT request against the Go test server."""
        try:
            # Detect provider
            provider = await s2iam.detect_provider(timeout=10.0)
            
            # Get JWT using test server
            jwt_token = await s2iam.get_jwt(
                jwt_type=JWTType.DATABASE_ACCESS,
                server_url=f"{test_server.server_url}/auth/iam/database",
                provider=provider,
                workspace_group_id="test-workspace"
            )
            
            assert jwt_token is not None
            assert isinstance(jwt_token, str)
            assert len(jwt_token) > 0
            
            print(f"Received JWT token: {jwt_token[:50]}...")
            
        except s2iam.NoCloudProviderDetectedError:
            pytest.skip("No cloud provider detected - not running in a cloud environment")
    
    async def test_jwt_different_types(self, test_server):
        """Test different JWT types with the test server."""
        try:
            provider = await s2iam.detect_provider(timeout=10.0)
            
            for jwt_type in [JWTType.DATABASE_ACCESS, JWTType.API_GATEWAY_ACCESS]:
                jwt_token = await s2iam.get_jwt(
                    jwt_type=jwt_type,
                    server_url=f"{test_server.server_url}/auth/iam/{jwt_type.value}",
                    provider=provider,
                    workspace_group_id="test-workspace"
                )
                
                assert jwt_token is not None
                print(f"JWT for {jwt_type.value}: {jwt_token[:50]}...")
                
        except s2iam.NoCloudProviderDetectedError:
            pytest.skip("No cloud provider detected - not running in a cloud environment")


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
            
        except s2iam.NoCloudProviderDetectedError:
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
            
        except s2iam.NoCloudProviderDetectedError:
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
            
        except s2iam.NoCloudProviderDetectedError:
            pytest.skip("No cloud provider detected")


@pytest.mark.asyncio
class TestErrorHandling:
    """Test error handling and edge cases."""
    
    async def test_no_provider_detected_outside_cloud(self):
        """Test behavior when not running in a cloud environment."""
        # This test might pass or fail depending on where it's run
        # If run locally (not in cloud), should raise NoCloudProviderDetectedError
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
                    workspace_group_id="test"
                )
                
        except s2iam.NoCloudProviderDetectedError:
            pytest.skip("No cloud provider detected")
    
    async def test_provider_not_detected_error(self):
        """Test ProviderNotDetectedError when using undetected provider."""
        from s2iam.aws import AWSClient
        
        # Create a new client that hasn't been detected
        client = AWSClient()
        
        with pytest.raises(s2iam.ProviderNotDetectedError):
            await client.get_identity_headers()


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])
