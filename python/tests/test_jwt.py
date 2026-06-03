"""Tests for JWT request behavior."""

import pytest

from s2iam import CloudIdentity, CloudProviderType, JWTType, get_jwt
from s2iam.jwt import _validate_server_url
from s2iam.models import CloudProviderClient


class FakeProvider(CloudProviderClient):
    async def fast_detect(self) -> None:
        return None

    async def detect(self) -> None:
        return None

    def get_type(self) -> CloudProviderType:
        return CloudProviderType.AWS

    def assume_role(self, role_identifier: str) -> "CloudProviderClient":
        return self

    async def get_identity_headers(self, additional_params=None) -> tuple[dict[str, str], CloudIdentity]:
        return {}, CloudIdentity(
            provider=CloudProviderType.AWS,
            identifier="arn:aws:iam::123456789012:role/TestRole",
            account_id="123456789012",
        )


@pytest.mark.asyncio
async def test_get_jwt_rejects_http_server_url_by_default():
    with pytest.raises(ValueError, match="server_url must use https"):
        await get_jwt(
            jwt_type=JWTType.DATABASE_ACCESS,
            workspace_group_id="test-workspace",
            server_url="http://localhost/auth/iam/database",
            provider=FakeProvider(),
        )


def test_validate_server_url_allows_http_when_explicitly_enabled():
    _validate_server_url("http://localhost/auth/iam/database", allow_http=True)
