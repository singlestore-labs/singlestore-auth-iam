"""Shared identity-format vocabulary and content-negotiation logic.

Clients send an ordered preference list of these tokens and the verifier chooses
the first one that is both server-supported and valid for the attested identity.
Tokens are stable forever and unknown/removed tokens are ignored, so the
vocabulary is forward- and backward-compatible across client/server versions.

This mirrors the Go reference (go/s2iam/models/identity_format.go).
"""

from typing import NamedTuple, Optional

from .models import CloudProviderType

# The identity-format vocabulary. Each token has a provider, a stable meaning,
# and a validity predicate over the attested data (see the per-provider candidate
# builders). v1 verifiers emit every token that is valid for the verified
# identity.

# AWS: raw caller ARN (always valid; current AWS default). Session-bearing for
# assumed-role sessions, so only pre-configurable when the session name is stable
# (e.g. the library-driven AssumeRole); otherwise prefer aws-iam-role-arn.
FORMAT_AWS_ARN = "aws-arn"
# AWS: base IAM role ARN (assumed-role sessions only).
FORMAT_AWS_IAM_ROLE_ARN = "aws-iam-role-arn"
# AWS: immutable RoleId (AROA...), the prefix of the STS UserId (assumed-role only).
FORMAT_AWS_ROLE_ID = "aws-role-id"
# GCP: service-account email (verified email only); GCP default (first).
FORMAT_GCP_SA_EMAIL = "gcp-sa-email"
# GCP: numeric subject (sub), immutable; always valid; GCP default (floor).
FORMAT_GCP_SA_UNIQUE_ID = "gcp-sa-unique-id"
# Azure: oid principal GUID; Azure default and floor (keeps oid-else-sub internally).
FORMAT_AZURE_OBJECT_ID = "azure-object-id"
# Azure: xms_mirid managed-identity ARM resource path (user-assigned MI only).
FORMAT_AZURE_RESOURCE_ID = "azure-resource-id"

# IdentityFormatPreferenceHeader is the request header carrying the client's
# ordered, comma-separated identity-format preference. It is the normative wire
# contract for protocol-only clients.
IDENTITY_FORMAT_PREFERENCE_HEADER = "X-S2IAM-Identity-Format-Preference"

# IdentityFormatPreferenceEnv is the environment variable the client reads to
# populate the preference header when no explicit option is given.
IDENTITY_FORMAT_PREFERENCE_ENV = "S2IAM_IDENTITY_FORMAT_PREFERENCE"

_FORMAT_PROVIDER = {
    FORMAT_AWS_ARN: CloudProviderType.AWS,
    FORMAT_AWS_IAM_ROLE_ARN: CloudProviderType.AWS,
    FORMAT_AWS_ROLE_ID: CloudProviderType.AWS,
    FORMAT_GCP_SA_EMAIL: CloudProviderType.GCP,
    FORMAT_GCP_SA_UNIQUE_ID: CloudProviderType.GCP,
    FORMAT_AZURE_OBJECT_ID: CloudProviderType.AZURE,
    FORMAT_AZURE_RESOURCE_ID: CloudProviderType.AZURE,
}

_DEFAULT_ORDER = {
    CloudProviderType.AWS: [FORMAT_AWS_ARN],
    CloudProviderType.GCP: [FORMAT_GCP_SA_EMAIL, FORMAT_GCP_SA_UNIQUE_ID],
    CloudProviderType.AZURE: [FORMAT_AZURE_OBJECT_ID],
}


class IdentityCandidate(NamedTuple):
    """A (format, value) pair that is valid for a verified identity.

    The value is always verifier-derived from attested data; the client supplies
    only format keys, never values.
    """

    format: str
    value: str


def format_provider(fmt: str) -> Optional[CloudProviderType]:
    """Return the cloud provider a format token belongs to, or None if unknown."""
    return _FORMAT_PROVIDER.get(fmt)


def default_identity_format_order(provider: CloudProviderType) -> list[str]:
    """Return the built-in default ordering for a provider.

    These defaults are byte-identical to the historical behavior: AWS keeps the
    raw ARN, GCP keeps verified-email-else-numeric-id, and Azure keeps the oid
    (with an internal sub floor). The new AWS ordering is opt-in via preference or
    server config.
    """
    return list(_DEFAULT_ORDER.get(provider, []))


def parse_identity_format_preference(value: Optional[str]) -> list[str]:
    """Parse a comma-separated preference list.

    Values are trimmed and empty entries dropped. Unknown tokens are preserved
    verbatim (ignored later during negotiation), keeping the parser
    forward-compatible with tokens added in newer releases.
    """
    if not value:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]


def select_identity_format(
    provider: CloudProviderType,
    valid: list[IdentityCandidate],
    client_pref: list[str],
    server_default: list[str],
) -> IdentityCandidate:
    """Deterministically choose the single identity format (and JWT sub).

    valid is the verifier-derived, ordered list of candidate formats valid for
    this identity (floor first; must be non-empty). client_pref is the client's
    requested ordering (may span providers and include unknown tokens).
    server_default is the configured default ordering for this provider.

    Algorithm: candidate order = client_pref filtered to this provider (unknown
    and other-provider tokens dropped), else server_default; choose the first
    candidate that is server-supported AND valid; fail closed to server_default,
    then to the floor (valid[0]), which is always valid.
    """
    valid_by_format = {c.format: c.value for c in valid}

    candidate_order = [f for f in client_pref if format_provider(f) == provider]
    if not candidate_order:
        candidate_order = server_default

    for fmt in candidate_order:
        if fmt in valid_by_format:
            return IdentityCandidate(fmt, valid_by_format[fmt])

    for fmt in server_default:
        if fmt in valid_by_format:
            return IdentityCandidate(fmt, valid_by_format[fmt])

    return valid[0]
