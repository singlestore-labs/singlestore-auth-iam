"""HTTPS validation for authentication server URLs."""

from urllib.parse import urlparse


def validate_auth_server_url(raw_url: str, *, allow_http: bool = False) -> None:
    """Ensure the authentication server URL uses HTTPS unless allow_http is set."""
    parsed = urlparse(raw_url)
    scheme = parsed.scheme
    if scheme == "https":
        return
    if scheme == "http" and allow_http:
        return
    if scheme == "http":
        raise ValueError(
            "authentication server URL must use HTTPS; pass allow_http=True for testing"
        )
    raise ValueError(f"authentication server URL must use HTTPS (got scheme {scheme!r})")
