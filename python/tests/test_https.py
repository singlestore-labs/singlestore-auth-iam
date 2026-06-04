"""Tests for HTTPS enforcement on authentication server URLs."""

from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from s2iam.https import validate_auth_server_url
from s2iam.jwt import get_jwt
from s2iam.models import CloudIdentity, CloudProviderClient, CloudProviderType, JWTType


class _StubProvider(CloudProviderClient):
    async def fast_detect(self) -> None:
        return None

    async def detect(self) -> None:
        return None

    def get_type(self) -> CloudProviderType:
        return CloudProviderType.AWS

    def assume_role(self, role_identifier: str) -> CloudProviderClient:
        return self

    async def get_identity_headers(
        self, additional_params: Optional[dict[str, str]] = None
    ) -> tuple[dict[str, str], CloudIdentity]:
        return {"X-Stub": "1"}, CloudIdentity(
            provider=CloudProviderType.AWS,
            identifier="arn:aws:iam::123456789012:role/test",
        )


def test_validate_auth_server_url_https():
    validate_auth_server_url("https://authsvc.singlestore.com/auth/iam/database")


def test_validate_auth_server_url_http_with_opt_in():
    validate_auth_server_url("http://localhost:8080/auth/iam/database", allow_http=True)


def test_validate_auth_server_url_rejects_http_by_default():
    with pytest.raises(ValueError, match="authentication server URL must use HTTPS"):
        validate_auth_server_url("http://localhost:8080/auth/iam/database")


def test_validate_auth_server_url_rejects_unsupported_scheme():
    with pytest.raises(ValueError, match="authentication server URL must use HTTPS"):
        validate_auth_server_url("ftp://example.com/auth/iam/database")


@pytest.mark.asyncio
async def test_get_jwt_rejects_http_without_allow_http():
    stub = _StubProvider()
    with pytest.raises(ValueError, match="authentication server URL must use HTTPS"):
        await get_jwt(
            jwt_type=JWTType.API_GATEWAY_ACCESS,
            server_url="http://localhost:8080/auth/iam/api",
            provider=stub,
        )


@pytest.mark.asyncio
async def test_get_jwt_allows_http_with_allow_http():
    stub = _StubProvider()
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={"jwt": "header.payload.sig"})
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.post.return_value = mock_response
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    with patch("s2iam.jwt.aiohttp.ClientSession", return_value=mock_session):
        token = await get_jwt(
            jwt_type=JWTType.API_GATEWAY_ACCESS,
            server_url="http://localhost:8080/auth/iam/api",
            allow_http=True,
            provider=stub,
        )

    assert token == "header.payload.sig"
