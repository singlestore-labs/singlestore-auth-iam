"""Unit tests for the client-side identity-format vocabulary + preference parsing.

The negotiation algorithm itself lives only in the Go verifier; its behavior is
covered end-to-end by the cloud integration tests (test_cloud_validation.py),
which exercise a real Go server. Here we only unit-test the pure client-side
preference parser.
"""

from s2iam.identity_format import (
    FORMAT_AWS_ARN,
    FORMAT_AWS_IAM_ROLE_ARN,
    IDENTITY_FORMAT_PREFERENCE_ENV,
    parse_identity_format_preference,
)
from s2iam.jwt import _PREFERENCE_UNSET, _resolve_identity_format_preference


def test_parse_identity_format_preference():
    assert parse_identity_format_preference(None) == []
    assert parse_identity_format_preference("") == []
    assert parse_identity_format_preference("aws-iam-role-arn,aws-arn") == [FORMAT_AWS_IAM_ROLE_ARN, FORMAT_AWS_ARN]
    # Whitespace trimmed, empty entries dropped, unknown tokens preserved verbatim.
    assert parse_identity_format_preference(" aws-arn , , future ") == [FORMAT_AWS_ARN, "future"]


def test_resolve_identity_format_preference_precedence(monkeypatch):
    """Option > env var > built-in default, mirroring Go's equivalent test."""
    monkeypatch.delenv(IDENTITY_FORMAT_PREFERENCE_ENV, raising=False)
    assert _resolve_identity_format_preference(_PREFERENCE_UNSET) == [FORMAT_AWS_IAM_ROLE_ARN, FORMAT_AWS_ARN]

    monkeypatch.setenv(IDENTITY_FORMAT_PREFERENCE_ENV, " aws-arn ")
    assert _resolve_identity_format_preference(_PREFERENCE_UNSET) == [FORMAT_AWS_ARN]
    # An explicit option overrides the env var.
    assert _resolve_identity_format_preference([FORMAT_AWS_IAM_ROLE_ARN]) == [FORMAT_AWS_IAM_ROLE_ARN]
    # An explicit empty option is honored (sends no header).
    assert _resolve_identity_format_preference([]) == []


def test_resolve_identity_format_preference_accepts_a_bare_string(monkeypatch):
    """A string is parsed as comma-separated, not split into characters."""
    monkeypatch.delenv(IDENTITY_FORMAT_PREFERENCE_ENV, raising=False)
    assert _resolve_identity_format_preference("aws-iam-role-arn") == [FORMAT_AWS_IAM_ROLE_ARN]
    assert _resolve_identity_format_preference("aws-iam-role-arn,aws-arn") == [
        FORMAT_AWS_IAM_ROLE_ARN,
        FORMAT_AWS_ARN,
    ]
