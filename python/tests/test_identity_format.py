"""Unit tests for the shared identity-format negotiation (mirrors the Go models tests)."""

from s2iam.identity_format import (
    FORMAT_AWS_ARN,
    FORMAT_AWS_IAM_ROLE_ARN,
    FORMAT_AWS_ROLE_ID,
    FORMAT_AZURE_OBJECT_ID,
    FORMAT_AZURE_RESOURCE_ID,
    FORMAT_GCP_SA_EMAIL,
    FORMAT_GCP_SA_UNIQUE_ID,
    IdentityCandidate,
    default_identity_format_order,
    format_provider,
    parse_identity_format_preference,
    select_identity_format,
)
from s2iam.models import CloudProviderType

AWS_ASSUMED_ROLE = [
    IdentityCandidate(
        FORMAT_AWS_ARN, "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session"
    ),
    IdentityCandidate(FORMAT_AWS_IAM_ROLE_ARN, "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole"),
    IdentityCandidate(FORMAT_AWS_ROLE_ID, "AROAEXAMPLE1234567890"),
]


def test_format_provider():
    assert format_provider(FORMAT_AWS_ARN) == CloudProviderType.AWS
    assert format_provider(FORMAT_GCP_SA_EMAIL) == CloudProviderType.GCP
    assert format_provider(FORMAT_AZURE_RESOURCE_ID) == CloudProviderType.AZURE
    assert format_provider("future-token") is None


def test_parse_identity_format_preference():
    assert parse_identity_format_preference(None) == []
    assert parse_identity_format_preference("") == []
    assert parse_identity_format_preference("aws-iam-role-arn,aws-arn") == [FORMAT_AWS_IAM_ROLE_ARN, FORMAT_AWS_ARN]
    assert parse_identity_format_preference(" aws-arn , , future ") == [FORMAT_AWS_ARN, "future"]


def test_default_order():
    assert default_identity_format_order(CloudProviderType.AWS) == [FORMAT_AWS_ARN]
    assert default_identity_format_order(CloudProviderType.GCP) == [FORMAT_GCP_SA_EMAIL, FORMAT_GCP_SA_UNIQUE_ID]
    assert default_identity_format_order(CloudProviderType.AZURE) == [FORMAT_AZURE_OBJECT_ID]


def test_new_preference_selects_base_role_arn():
    chosen = select_identity_format(
        CloudProviderType.AWS,
        AWS_ASSUMED_ROLE,
        [FORMAT_AWS_IAM_ROLE_ARN, FORMAT_AWS_ARN],
        default_identity_format_order(CloudProviderType.AWS),
    )
    assert chosen == IdentityCandidate(
        FORMAT_AWS_IAM_ROLE_ARN, "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole"
    )


def test_legacy_preference_keeps_raw_arn_with_session():
    chosen = select_identity_format(
        CloudProviderType.AWS,
        AWS_ASSUMED_ROLE,
        [FORMAT_AWS_ARN],
        default_identity_format_order(CloudProviderType.AWS),
    )
    assert chosen.format == FORMAT_AWS_ARN
    assert chosen.value.endswith("/example-session")


def test_iam_user_falls_back_to_raw_arn():
    valid = [IdentityCandidate(FORMAT_AWS_ARN, "arn:aws:iam::111122223333:user/alice")]
    chosen = select_identity_format(
        CloudProviderType.AWS,
        valid,
        [FORMAT_AWS_IAM_ROLE_ARN, FORMAT_AWS_ARN],
        default_identity_format_order(CloudProviderType.AWS),
    )
    assert chosen == IdentityCandidate(FORMAT_AWS_ARN, "arn:aws:iam::111122223333:user/alice")


def test_other_provider_and_unknown_tokens_ignored():
    chosen = select_identity_format(
        CloudProviderType.AWS,
        AWS_ASSUMED_ROLE,
        [FORMAT_GCP_SA_EMAIL, "future"],
        default_identity_format_order(CloudProviderType.AWS),
    )
    assert chosen.format == FORMAT_AWS_ARN


def test_empty_intersection_fails_closed_to_floor():
    valid = [IdentityCandidate(FORMAT_AWS_ARN, "arn:aws:iam::1:user/x")]
    chosen = select_identity_format(CloudProviderType.AWS, valid, [FORMAT_AWS_ROLE_ID], [FORMAT_AWS_IAM_ROLE_ARN])
    assert chosen == IdentityCandidate(FORMAT_AWS_ARN, "arn:aws:iam::1:user/x")


def test_azure_resource_id_selectable():
    resource_id = (
        "/subscriptions/SUB/resourcegroups/RG/providers/" "Microsoft.ManagedIdentity/userAssignedIdentities/my-identity"
    )
    valid = [
        IdentityCandidate(FORMAT_AZURE_OBJECT_ID, "11111111-2222-3333-4444-555555555555"),
        IdentityCandidate(FORMAT_AZURE_RESOURCE_ID, resource_id),
    ]
    chosen = select_identity_format(
        CloudProviderType.AZURE,
        valid,
        [FORMAT_AZURE_RESOURCE_ID, FORMAT_AZURE_OBJECT_ID],
        default_identity_format_order(CloudProviderType.AZURE),
    )
    assert chosen.format == FORMAT_AZURE_RESOURCE_ID
