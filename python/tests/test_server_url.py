"""Unit tests for authentication server URL resolution.

The Go, Python, and Java clients resolve the server URL the same way — explicit
argument, then S2IAM_SERVER_URL, then the built-in default — and expand the same
:cloudProvider and :jwtType placeholders, so one environment setting configures a
mixed-language fleet.
"""

from s2iam.jwt import (
    DEFAULT_SERVER_URL,
    SERVER_URL_ENV,
    _expand_server_url,
    _resolve_server_url,
)
from s2iam.models import JWTType


def test_resolve_server_url_precedence(monkeypatch):
    monkeypatch.delenv(SERVER_URL_ENV, raising=False)
    monkeypatch.delenv("S2IAM_JWT_SERVER_URL", raising=False)
    assert _resolve_server_url(JWTType.DATABASE_ACCESS, None) == DEFAULT_SERVER_URL.format(jwt_type="database")
    assert _resolve_server_url(JWTType.API_GATEWAY_ACCESS, None) == DEFAULT_SERVER_URL.format(jwt_type="api")

    monkeypatch.setenv(SERVER_URL_ENV, "https://auth.example.com/auth/iam/:jwtType")
    assert _resolve_server_url(JWTType.DATABASE_ACCESS, None) == "https://auth.example.com/auth/iam/:jwtType"

    assert _resolve_server_url(JWTType.DATABASE_ACCESS, "https://explicit.example.com/auth") == (
        "https://explicit.example.com/auth"
    )


def test_resolve_server_url_honors_the_legacy_env_var(monkeypatch):
    monkeypatch.delenv(SERVER_URL_ENV, raising=False)
    monkeypatch.setenv("S2IAM_JWT_SERVER_URL", "https://legacy.example.com/auth")
    assert _resolve_server_url(JWTType.DATABASE_ACCESS, None) == "https://legacy.example.com/auth"

    monkeypatch.setenv(SERVER_URL_ENV, "https://current.example.com/auth")
    assert _resolve_server_url(JWTType.DATABASE_ACCESS, None) == "https://current.example.com/auth"


def test_expand_server_url():
    assert _expand_server_url(
        "https://auth.example.com/:cloudProvider/iam/:jwtType", JWTType.API_GATEWAY_ACCESS, "aws"
    ) == ("https://auth.example.com/aws/iam/api")

    # A URL carrying neither placeholder is left alone.
    assert _expand_server_url("https://auth.example.com/auth", JWTType.DATABASE_ACCESS, "gcp") == (
        "https://auth.example.com/auth"
    )
