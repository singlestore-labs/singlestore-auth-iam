"""Unit tests for the AWS identity-format candidates and claims.

Assumed-role sessions expose the raw ARN (floor), the base IAM role ARN, and the
immutable RoleId; the raw ARN preserves the session (byte-identical to today) and
only aws-iam-role-arn / aws-role-id strip it. Mirrors the Go TestAWSCandidates.
"""

from s2iam.aws import (
    CLAIM_ASSUMED_ROLE_ARN,
    CLAIM_ROLE_SESSION_NAME,
    CLAIM_USER_ID,
    _aws_candidates,
    _aws_identity_claims,
)
from s2iam.identity_format import (
    FORMAT_AWS_ARN,
    FORMAT_AWS_IAM_ROLE_ARN,
    FORMAT_AWS_ROLE_ID,
    IdentityCandidate,
)


def test_assumed_role_candidates():
    arn = "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session"
    candidates = _aws_candidates(arn, "111122223333", "AROAEXAMPLE1234567890:example-session")
    assert candidates == [
        IdentityCandidate(FORMAT_AWS_ARN, arn),
        IdentityCandidate(FORMAT_AWS_IAM_ROLE_ARN, "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole"),
        IdentityCandidate(FORMAT_AWS_ROLE_ID, "AROAEXAMPLE1234567890"),
    ]
    # The always-valid floor is the raw caller ARN (session kept).
    assert candidates[0] == IdentityCandidate(FORMAT_AWS_ARN, arn)


def test_base_role_arn_is_session_independent():
    a = _aws_candidates(
        "arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/s2iam-session",
        "503396375767",
    )[1]
    b = _aws_candidates(
        "arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/some-other-session",
        "503396375767",
    )[1]
    assert a == b == IdentityCandidate(FORMAT_AWS_IAM_ROLE_ARN, "arn:aws:iam::503396375767:role/NoPermissionsRole")


def test_base_role_arn_preserves_partition():
    # GovCloud/China: the derived base role ARN must keep the source partition so
    # it stays byte-identical to the Go verifier's issued JWT sub.
    gov = _aws_candidates(
        "arn:aws-us-gov:sts::503396375767:assumed-role/NoPermissionsRole/s2iam-session",
        "503396375767",
    )[1]
    assert gov == IdentityCandidate(FORMAT_AWS_IAM_ROLE_ARN, "arn:aws-us-gov:iam::503396375767:role/NoPermissionsRole")


def test_iam_user_has_only_the_raw_arn_floor():
    arn = "arn:aws:iam::123456789012:user/Alice"
    candidates = _aws_candidates(arn, "123456789012", "AIDAEXAMPLE")
    assert candidates == [IdentityCandidate(FORMAT_AWS_ARN, arn)]


def test_identity_claims_preserve_alternates():
    arn = "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session"
    claims = _aws_identity_claims(arn, "AROAEXAMPLE1234567890:example-session")
    assert claims[CLAIM_ASSUMED_ROLE_ARN] == arn
    assert claims[CLAIM_ROLE_SESSION_NAME] == "example-session"
    assert claims[CLAIM_USER_ID] == "AROAEXAMPLE1234567890:example-session"

    user_claims = _aws_identity_claims("arn:aws:iam::123456789012:user/Alice", "AIDAEXAMPLE")
    assert user_claims[CLAIM_USER_ID] == "AIDAEXAMPLE"
    assert CLAIM_ASSUMED_ROLE_ARN not in user_claims
