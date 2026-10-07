"""Unit tests for the client-side identity-format vocabulary + preference parsing.

The negotiation algorithm itself lives only in the Go verifier; its behavior is
covered end-to-end by the cloud integration tests (test_cloud_validation.py),
which exercise a real Go server. Here we only unit-test the pure client-side
preference parser.
"""

from s2iam.identity_format import (
    FORMAT_AWS_ARN,
    FORMAT_AWS_IAM_ROLE_ARN,
    parse_identity_format_preference,
)


def test_parse_identity_format_preference():
    assert parse_identity_format_preference(None) == []
    assert parse_identity_format_preference("") == []
    assert parse_identity_format_preference("aws-iam-role-arn,aws-arn") == [FORMAT_AWS_IAM_ROLE_ARN, FORMAT_AWS_ARN]
    # Whitespace trimmed, empty entries dropped, unknown tokens preserved verbatim.
    assert parse_identity_format_preference(" aws-arn , , future ") == [FORMAT_AWS_ARN, "future"]
