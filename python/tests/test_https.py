import pytest

from s2iam.https import validate_auth_server_url


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
