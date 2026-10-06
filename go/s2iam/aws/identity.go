package aws

import (
	"fmt"
	"strings"

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
func awsIdentityClaims(arn, userID string) map[string]string {
	claims := map[string]string{}
	if userID != "" {
		claims[ClaimUserID] = userID
	}
	if _, sessionName, ok := parseAssumedRoleARN(arn); ok {
		claims[ClaimAssumedRoleArn] = arn
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
func awsCandidates(arn, account, userID string) []models.IdentityCandidate {
	candidates := []models.IdentityCandidate{
		{Format: models.FormatAWSARN, Value: arn},
	}

	if roleName, _, ok := parseAssumedRoleARN(arn); ok {
		candidates = append(candidates, models.IdentityCandidate{
			Format: models.FormatAWSIAMRoleARN,
			Value:  fmt.Sprintf("arn:aws:iam::%s:role/%s", account, roleName),
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

// parseAssumedRoleARN returns the role name and session name of an STS
// assumed-role ARN (arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION). ok is false
// for any other ARN shape.
func parseAssumedRoleARN(arn string) (roleName, sessionName string, ok bool) {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[2] != "sts" {
		return "", "", false
	}
	// resource = assumed-role/ROLE/SESSION; neither ROLE nor SESSION may contain '/'.
	segments := strings.SplitN(parts[5], "/", 3)
	if len(segments) < 2 || segments[0] != "assumed-role" || segments[1] == "" {
		return "", "", false
	}
	if len(segments) == 3 {
		sessionName = segments[2]
	}
	return segments[1], sessionName, true
}

// arnResourceType extracts the resource type (the segment before the first '/'
// in the resource portion of an ARN), e.g. "role", "user", "assumed-role".
func arnResourceType(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 6 {
		resourceParts := strings.Split(parts[5], "/")
		if len(resourceParts) >= 2 {
			return resourceParts[0]
		}
	}
	return ""
}
