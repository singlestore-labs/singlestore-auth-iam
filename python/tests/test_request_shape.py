"""Request-shape details that have to match across Go, Python, and Java."""

from s2iam.gcp import impersonation_url
from s2iam.jwt import _with_workspace_group_query


def test_database_jwt_url_carries_workspace_group_query():
    got = _with_workspace_group_query(
        "https://authsvc.example.com/auth/iam/database",
        "11111111-1111-4111-8111-111111111111",
    )
    assert got == (
        "https://authsvc.example.com/auth/iam/database" "?workspaceGroupID=11111111-1111-4111-8111-111111111111"
    )


def test_database_jwt_url_keeps_existing_query():
    got = _with_workspace_group_query(
        "https://authsvc.example.com/auth/iam/database?x=1",
        "wg",
    )
    assert got == "https://authsvc.example.com/auth/iam/database?x=1&workspaceGroupID=wg"


def test_impersonation_url_encodes_the_service_account_as_one_segment():
    email = "service-account@project-id.iam.gserviceaccount.com"
    assert impersonation_url(email) == (
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + email + ":generateIdToken"
    )
    encoded = impersonation_url("evil/other:generateAccessToken")
    assert "/evil/other" not in encoded
    assert "evil%2Fother:generateAccessToken" in encoded
