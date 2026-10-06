"""Unit tests for the AWS canonical identity mapping.

Assumed-role sessions collapse to their base IAM role ARN; the caller-chosen STS
session name does not affect the issued identity. Mirrors the Go
TestCanonicalIdentity.
"""

from s2iam.aws import (
    CLAIM_ASSUMED_ROLE_ARN,
    CLAIM_ROLE_SESSION_NAME,
    CLAIM_USER_ID,
    canonical_identity,
)


def test_assumed_role_collapses_to_base_role_arn():
    arn = "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session"
    identifier, resource_type, claims = canonical_identity(arn, "111122223333", "AROAEXAMPLE1234567890:example-session")
    assert identifier == "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole"
    assert resource_type == "role"
    assert claims[CLAIM_ASSUMED_ROLE_ARN] == arn
    assert claims[CLAIM_ROLE_SESSION_NAME] == "example-session"
    assert claims[CLAIM_USER_ID] == "AROAEXAMPLE1234567890:example-session"


def test_session_name_does_not_affect_identity():
    a = canonical_identity(
        "arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/s2iam-session",
        "503396375767",
    )[0]
    b = canonical_identity(
        "arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/some-other-session",
        "503396375767",
    )[0]
    assert a == b == "arn:aws:iam::503396375767:role/NoPermissionsRole"


def test_iam_user_unchanged():
    identifier, resource_type, claims = canonical_identity(
        "arn:aws:iam::123456789012:user/Alice", "123456789012", "AIDAEXAMPLE"
    )
    assert identifier == "arn:aws:iam::123456789012:user/Alice"
    assert resource_type == "user"
    assert CLAIM_ASSUMED_ROLE_ARN not in claims
