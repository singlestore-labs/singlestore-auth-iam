package models

import "strings"

// IdentityFormat is a stable, lowercase, provider-prefixed token naming one of
// the 1:1 representations of a verified cloud principal (for example the raw AWS
// ARN vs. the base IAM role ARN). Clients send an ordered preference list of
// these tokens and the verifier chooses the first one that is both
// server-supported and valid for the attested identity (content negotiation).
//
// Tokens are stable forever and unknown/removed tokens are ignored, so the
// vocabulary is forward- and backward-compatible across client/server versions.
type IdentityFormat string

// The identity-format vocabulary. Each token has a provider, a stable meaning,
// and a validity predicate over the attested data (see the per-provider
// candidate builders). v1 verifiers emit every token that is valid for the
// verified identity.
const (
	// FormatAWSARN is the raw caller ARN as returned by GetCallerIdentity (IAM
	// user, assumed-role session, root, or federated-user). Always valid: it is the
	// AWS floor and the form issued when a request carries no preference. For an
	// assumed-role session it is session-bearing
	// (arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION) and is only pre-configurable
	// when the session name is stable (e.g. the library-driven AssumeRole, which
	// uses a stable default session name); otherwise prefer aws-iam-role-arn.
	FormatAWSARN IdentityFormat = "aws-arn"
	// FormatAWSIAMRoleARN is the base IAM role ARN (arn:aws:iam::ACCOUNT:role/ROLE)
	// to which an assumed-role session collapses. Valid only when the caller is an
	// assumed-role session. The client libraries request it first as of v0.6.0.
	FormatAWSIAMRoleARN IdentityFormat = "aws-iam-role-arn"
	// FormatAWSRoleID is the immutable RoleId (AROA...), the prefix of the STS
	// UserId. Valid only when the caller is an assumed-role session.
	FormatAWSRoleID IdentityFormat = "aws-role-id"

	// FormatGCPSAEmail is the service-account email. Valid only when the token
	// carries a verified email (email present AND email_verified). GCP default
	// (first).
	FormatGCPSAEmail IdentityFormat = "gcp-sa-email"
	// FormatGCPSAUniqueID is the numeric subject (sub), which is immutable. Always
	// valid. GCP default (second / floor).
	FormatGCPSAUniqueID IdentityFormat = "gcp-sa-unique-id"

	// FormatAzureObjectID is the oid principal GUID. This is the Azure default and
	// floor (it keeps today's oid-else-sub behavior internally).
	FormatAzureObjectID IdentityFormat = "azure-object-id"
	// FormatAzureResourceID is the xms_mirid managed-identity ARM resource path.
	// Valid only for a user-assigned managed identity (xms_mirid present).
	FormatAzureResourceID IdentityFormat = "azure-resource-id"
)

const (
	// IdentityFormatPreferenceHeader is the request header carrying the client's
	// ordered, comma-separated identity-format preference. It is the normative wire
	// contract for protocol-only clients.
	IdentityFormatPreferenceHeader = "X-S2IAM-Identity-Format-Preference"

	// IdentityFormatPreferenceEnv is the environment variable the client libraries
	// read to populate the preference header when no explicit option is given.
	IdentityFormatPreferenceEnv = "S2IAM_IDENTITY_FORMAT_PREFERENCE"
)

// IdentityCandidate is a (format, value) pair that is valid for a verified
// identity. The value is always verifier-derived from attested data; the client
// supplies only format keys, never values.
type IdentityCandidate struct {
	Format IdentityFormat
	Value  string
}

// defaultIdentityFormats is the single canonical ordering of every identity
// format, and the only place this ordering is defined. SelectIdentityFormat uses
// it as the final fallback when neither the client preference nor the server
// override selects a format.
//
// It lists all formats, but order is what matters: within each provider the
// historical default comes first, so for an identity with no preference the
// first valid token reproduces today's behavior byte-for-byte — AWS the raw ARN,
// GCP the verified email else the numeric id, Azure the oid. The remaining
// per-provider formats (aws-iam-role-arn, aws-role-id, azure-resource-id) follow
// their provider's default and are therefore only ever chosen when explicitly
// requested via the client preference or server override. Treat as read-only.
var defaultIdentityFormats = []IdentityFormat{
	FormatAWSARN, FormatAWSIAMRoleARN, FormatAWSRoleID,
	FormatGCPSAEmail, FormatGCPSAUniqueID,
	FormatAzureObjectID, FormatAzureResourceID,
}

// ParseIdentityFormatPreference parses a comma-separated preference list: values
// are trimmed and empty entries dropped. Unknown tokens are preserved verbatim
// (they are ignored later during negotiation), keeping the parser
// forward-compatible with tokens added in newer releases.
func ParseIdentityFormatPreference(s string) []IdentityFormat {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	formats := make([]IdentityFormat, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		formats = append(formats, IdentityFormat(p))
	}
	return formats
}

// SelectIdentityFormat performs the deterministic negotiation that chooses the
// single identity format (and therefore the JWT sub) for a verified identity.
//
// valid is the verifier-derived, ordered list of candidate formats that are
// valid for this identity (floor first; must be non-empty). clientPref is the
// client's requested ordering (may span providers and include unknown tokens).
// serverOverride is the instance's configured override ordering (may be empty).
//
// The algorithm walks three preference lists in priority order — the client
// preference, the server override, then the static built-in defaultIdentityFormats
// — and returns the first token valid for this identity; if none match it fails
// closed to the floor (valid[0]), which is always valid, so selection never
// fails. Concatenating the built-in last means every provider keeps its
// historical default even when the override names only other providers.
//
// No provider filtering is needed: valid is already scoped to this identity's
// provider, so unknown tokens and tokens belonging to other providers simply
// miss the validByFormat lookup and are skipped. Negotiation can only reorder
// among already-valid, verifier-derived representations of the same principal;
// it can never broaden a match or cross identities.
func SelectIdentityFormat(valid []IdentityCandidate, clientPref, serverOverride []IdentityFormat) (IdentityFormat, string) {
	validByFormat := make(map[IdentityFormat]string, len(valid))
	for _, c := range valid {
		validByFormat[c.Format] = c.Value
	}

	for _, list := range [][]IdentityFormat{clientPref, serverOverride, defaultIdentityFormats} {
		for _, f := range list {
			if v, ok := validByFormat[f]; ok {
				return f, v
			}
		}
	}
	return valid[0].Format, valid[0].Value
}
