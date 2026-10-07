package aws

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

// Claim keys populated in CloudIdentity.AdditionalClaims for AWS identities.
// These alternates are preserved for registration-preview and audit regardless
// of which identity format is negotiated.
const (
	// ClaimUserID is the raw STS UserId (e.g. AROAEXAMPLE:session). The portion
	// before the colon is the stable RoleId of the underlying IAM role.
	ClaimUserID = "UserId"
	// ClaimAssumedRoleArn is the raw STS assumed-role ARN, preserved for audit when
	// an assumed-role identity may be collapsed to its base IAM role ARN.
	ClaimAssumedRoleArn = "AssumedRoleArn"
	// ClaimRoleSessionName is the (caller-chosen) STS session name, preserved for
	// audit. It does not affect the issued identity.
	ClaimRoleSessionName = "RoleSessionName"
)

// awsIdentityClaims builds the AdditionalClaims for an AWS identity. The raw STS
// assumed-role ARN, the role session name, and the STS UserId (whose prefix is
// the role's immutable RoleId) are preserved so the auth service can show
// alternates for registration-preview and audit, independent of the negotiated
// identity format.
func awsIdentityClaims(callerARN, userID string) map[string]string {
	claims := map[string]string{}
	if userID != "" {
		claims[ClaimUserID] = userID
	}
	if _, _, sessionName, ok := parseAssumedRoleARN(callerARN); ok {
		claims[ClaimAssumedRoleArn] = callerARN
		if sessionName != "" {
			claims[ClaimRoleSessionName] = sessionName
		}
	}
	return claims
}

// awsCandidates returns the identity formats that are valid for the attested
// GetCallerIdentity result, in natural order with the always-valid floor first.
//
//   - aws-arn (floor, always): the raw caller ARN.
//   - aws-iam-role-arn (assumed-role only): the base IAM role ARN
//     (arn:aws:iam::ACCOUNT:role/ROLE). The STS session name is caller-chosen and
//     is not a trustworthy authorization boundary; the IAM role is gated by its
//     trust policy, and role names are unique within an account, so the base role
//     ARN is a stable, unique identifier for the role.
//   - aws-role-id (assumed-role only): the immutable RoleId (AROA...), the prefix
//     of the STS UserId.
//
// Note: the STS assumed-role ARN omits the IAM path for every role, so the
// derived base role ARN is the path-less canonical form
// (arn:aws:iam::ACCOUNT:role/ROLE); register the cloud principal / database user
// using that form.
//
// This must stay identical between the client and the verifier so the
// client-computed identity matches the issued JWT sub.
func awsCandidates(callerARN, account, userID string) []models.IdentityCandidate {
	candidates := []models.IdentityCandidate{
		{Format: models.FormatAWSARN, Value: callerARN},
	}

	if parsed, roleName, _, ok := parseAssumedRoleARN(callerARN); ok {
		// Derive the base IAM role ARN, preserving the source partition (aws,
		// aws-us-gov, aws-cn) and dropping the region (IAM is global). The STS
		// assumed-role ARN omits the IAM path, so this is the path-less canonical
		// form arn:PARTITION:iam::ACCOUNT:role/ROLE.
		baseRoleARN := arn.ARN{
			Partition: parsed.Partition,
			Service:   "iam",
			AccountID: account,
			Resource:  "role/" + roleName,
		}.String()
		candidates = append(candidates, models.IdentityCandidate{
			Format: models.FormatAWSIAMRoleARN,
			Value:  baseRoleARN,
		})
		if roleID := roleIDFromUserID(userID); roleID != "" {
			candidates = append(candidates, models.IdentityCandidate{
				Format: models.FormatAWSRoleID,
				Value:  roleID,
			})
		}
	}

	return candidates
}

// roleIDFromUserID returns the immutable RoleId portion of an STS UserId, i.e.
// the segment before the ':' (UserId is "AROA...:session" for assumed roles).
func roleIDFromUserID(userID string) string {
	if i := strings.IndexByte(userID, ':'); i >= 0 {
		return userID[:i]
	}
	return ""
}

// parseAssumedRoleARN returns the parsed ARN plus the role name and session name
// of an STS assumed-role ARN (arn:PARTITION:sts::ACCOUNT:assumed-role/ROLE/SESSION).
// ok is false for any other ARN shape. The resource sub-structure
// (assumed-role/ROLE/SESSION) is not modeled by the SDK's arn package, so it is
// split here; neither ROLE nor SESSION may contain '/'.
func parseAssumedRoleARN(s string) (parsed arn.ARN, roleName, sessionName string, ok bool) {
	parsed, err := arn.Parse(s)
	if err != nil || parsed.Service != "sts" {
		return arn.ARN{}, "", "", false
	}
	segments := strings.SplitN(parsed.Resource, "/", 3)
	if len(segments) < 2 || segments[0] != "assumed-role" || segments[1] == "" {
		return arn.ARN{}, "", "", false
	}
	if len(segments) == 3 {
		sessionName = segments[2]
	}
	return parsed, segments[1], sessionName, true
}

// arnResourceType extracts the resource type (the segment before the first '/'
// in the resource portion of an ARN), e.g. "role", "user", "assumed-role".
// Returns "" for a malformed ARN or a resource with no '/' delimiter.
func arnResourceType(s string) string {
	parsed, err := arn.Parse(s)
	if err != nil {
		return ""
	}
	resourceType, _, found := strings.Cut(parsed.Resource, "/")
	if !found {
		return ""
	}
	return resourceType
}
