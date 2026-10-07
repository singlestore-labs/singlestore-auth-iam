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
	// user, assumed-role session, root, or federated-user). Always valid and the
	// current AWS default. For an assumed-role session it is session-bearing
	// (arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION) and is only pre-configurable
	// when the session name is stable (e.g. the library-driven AssumeRole, which
	// uses a stable default session name); otherwise prefer aws-iam-role-arn.
	FormatAWSARN IdentityFormat = "aws-arn"
	// FormatAWSIAMRoleARN is the base IAM role ARN (arn:aws:iam::ACCOUNT:role/ROLE)
	// to which an assumed-role session collapses. Valid only when the caller is an
	// assumed-role session.
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

// DefaultIdentityFormats returns the single built-in default ordering: a flat
// list spanning providers (each token names its own provider). A verifier uses
// it when a request carries no (valid) preference and no server default is
// configured. The full list is supplied as-is to every provider verifier — no
// per-provider filtering is needed, because negotiation only ever returns a
// format that is valid for the identity at hand, so tokens belonging to other
// providers are harmlessly skipped. These defaults are deliberately byte-
// identical to the historical behavior: AWS keeps the raw ARN, GCP keeps
// verified-email-else-numeric-id, and Azure keeps the oid (with an internal sub
// floor). The new AWS ordering ([aws-iam-role-arn, aws-arn]) is opt-in via
// preference or server config. A fresh slice is returned so callers cannot
// mutate the shared default.
func DefaultIdentityFormats() []IdentityFormat {
	return []IdentityFormat{
		FormatAWSARN,
		FormatGCPSAEmail, FormatGCPSAUniqueID,
		FormatAzureObjectID,
	}
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
// serverDefault is the instance's configured default ordering (may be nil, and
// may name only some providers).
//
// The algorithm: walk clientPref, then serverDefault, then the built-in
// DefaultIdentityFormats, and return the first token that is valid for this
// identity; if none match, fail closed to the floor (valid[0]), which is always
// valid — so selection never fails.
//
// Appending the built-in defaults last guarantees that every provider keeps its
// historical default even when serverDefault only names other providers (e.g.
// an instance configured with an AWS-only default list must not downgrade a
// verified GCP email to the numeric floor). No provider filtering is needed:
// valid is already scoped to this identity's provider, so unknown tokens and
// tokens belonging to other providers simply miss the validByFormat lookup and
// are skipped.
//
// Negotiation can only reorder among already-valid, verifier-derived
// representations of the same principal; it can never broaden a match or cross
// identities.
func SelectIdentityFormat(valid []IdentityCandidate, clientPref, serverDefault []IdentityFormat) (IdentityFormat, string) {
	validByFormat := make(map[IdentityFormat]string, len(valid))
	for _, c := range valid {
		validByFormat[c.Format] = c.Value
	}

	builtin := DefaultIdentityFormats()
	candidateOrder := make([]IdentityFormat, 0, len(clientPref)+len(serverDefault)+len(builtin))
	candidateOrder = append(candidateOrder, clientPref...)
	candidateOrder = append(candidateOrder, serverDefault...)
	candidateOrder = append(candidateOrder, builtin...)
	for _, f := range candidateOrder {
		if v, ok := validByFormat[f]; ok {
			return f, v
		}
	}
	return valid[0].Format, valid[0].Value
}
