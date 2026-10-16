"""Database JWT URLs must carry workspaceGroupID the way Go and Java do."""

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
