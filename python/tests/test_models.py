"""
Basic unit tests for s2iam models and interfaces.

These tests focus on the data structures and interfaces rather than
cloud provider functionality, which is tested in integration tests.
"""

import pytest

from s2iam.models import (
    AssumeRoleNotSupported,
    CloudIdentity,
    CloudProviderNotFound,
    CloudProviderType,
    JWTType,
    ProviderIdentityUnavailable,
    ProviderNotDetected,
    S2IAMError,
)


class TestModels:
    """Test the data models."""

    def test_cloud_provider_type_enum(self):
        """Test CloudProviderType enum."""
        assert CloudProviderType.AWS.value == "aws"
        assert CloudProviderType.GCP.value == "gcp"
        assert CloudProviderType.AZURE.value == "azure"

    def test_jwt_type_enum(self):
        """Test JWTType enum."""
        assert JWTType.DATABASE_ACCESS.value == "database"
        assert JWTType.API_GATEWAY_ACCESS.value == "api"

    def test_cloud_identity_creation(self):
        """Test CloudIdentity dataclass."""
        identity = CloudIdentity(
            provider=CloudProviderType.AWS,
            identifier="arn:aws:iam::123456789012:role/TestRole",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws-role",
            additional_claims={"custom": "value"},
        )

        assert identity.provider == CloudProviderType.AWS
        assert identity.identifier == "arn:aws:iam::123456789012:role/TestRole"
        assert identity.account_id == "123456789012"
        assert identity.region == "us-east-1"
        assert identity.resource_type == "aws-role"
        assert identity.additional_claims == {"custom": "value"}

    def test_cloud_identity_defaults(self):
        """Test CloudIdentity with default values."""
        identity = CloudIdentity(
            provider=CloudProviderType.GCP, identifier="test-identity"
        )

        assert identity.provider == CloudProviderType.GCP
        assert identity.identifier == "test-identity"
        assert identity.account_id == ""
        assert identity.region == ""
        assert identity.resource_type == ""
        assert identity.additional_claims == {}


class TestExceptions:
    """Test the exception hierarchy."""

    def test_base_exception(self):
        """Test S2IAMError base exception."""
        error = S2IAMError("test error")
        assert str(error) == "test error"
        assert isinstance(error, Exception)

    def test_cloud_provider_not_found(self):
        """Test CloudProviderNotFound."""
        error = CloudProviderNotFound("no provider")
        assert str(error) == "no provider"
        assert isinstance(error, S2IAMError)

    def test_provider_not_detected(self):
        """Test ProviderNotDetected."""
        error = ProviderNotDetected("not detected")
        assert str(error) == "not detected"
        assert isinstance(error, S2IAMError)

    def test_provider_identity_unavailable(self):
        """Test ProviderIdentityUnavailable."""
        error = ProviderIdentityUnavailable("no identity")
        assert str(error) == "no identity"
        assert isinstance(error, S2IAMError)

    def test_assume_role_not_supported(self):
        """Test AssumeRoleNotSupported."""
        error = AssumeRoleNotSupported("not supported")
        assert str(error) == "not supported"
        assert isinstance(error, S2IAMError)


class TestInterfaces:
    """Test the abstract interfaces."""

    def test_logger_protocol(self):
        """Test Logger protocol implementation."""

        class TestLogger:
            def __init__(self):
                self.messages = []

            def log(self, message: str) -> None:
                self.messages.append(message)

        logger = TestLogger()
        logger.log("test message")
        assert logger.messages == ["test message"]

        # This should not raise any type errors
        assert isinstance(
            logger, object
        )  # Logger is a Protocol, so this is basic check

    def test_cloud_provider_client_interface(self):
        """Test CloudProviderClient abstract interface."""
        from s2iam.models import CloudProviderClient

        # Should not be able to instantiate abstract class
        with pytest.raises(TypeError):
            CloudProviderClient()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
