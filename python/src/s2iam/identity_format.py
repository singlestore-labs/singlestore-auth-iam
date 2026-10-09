"""Shared identity-format vocabulary and preference parsing.

Clients send an ordered preference list of these tokens and the server-side
verifier chooses the first one that is both server-supported and valid for the
attested identity. Tokens are stable forever and unknown/removed tokens are
ignored, so the vocabulary is forward- and backward-compatible across
client/server versions.

The negotiation algorithm itself lives only in the Go verifier
(go/s2iam/models/identity_format.go, SelectIdentityFormat); this client library
just names the vocabulary and parses the preference list. End-to-end negotiation
behavior is covered by integration tests that exercise a real Go server.
"""

from typing import NamedTuple, Optional

# The identity-format vocabulary. Each token has a provider, a stable meaning,
# and a validity predicate over the attested data (see the per-provider candidate
# builders). v1 verifiers emit every token that is valid for the verified
# identity.

# AWS: raw caller ARN (always valid; the AWS floor and the form issued when a request
# carries no preference). Session-bearing for assumed-role sessions, so only
# pre-configurable when the session name is stable (e.g. the library-driven
# AssumeRole); otherwise prefer aws-iam-role-arn.
FORMAT_AWS_ARN = "aws-arn"
# AWS: base IAM role ARN (assumed-role sessions only); requested first by the client
# as of v0.6.0.
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


class IdentityCandidate(NamedTuple):
    """A (format, value) pair that is valid for a verified identity.

    The value is always verifier-derived from attested data; the client supplies
    only format keys, never values.
    """

    format: str
    value: str


def parse_identity_format_preference(value: Optional[str]) -> list[str]:
    """Parse a comma-separated preference list.

    Values are trimmed and empty entries dropped. Unknown tokens are preserved
    verbatim (ignored later during negotiation by the server), keeping the parser
    forward-compatible with tokens added in newer releases.
    """
    if not value:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]
