package aws

import (
	"fmt"
	"strings"
)

// Claim keys populated in CloudIdentity.AdditionalClaims for AWS identities.
const (
	// ClaimUserID is the raw STS UserId (e.g. AROAEXAMPLE:session). The portion
	// before the colon is the stable RoleId of the underlying IAM role.
	ClaimUserID = "UserId"
	// ClaimAssumedRoleArn is the raw STS assumed-role ARN, preserved for audit when
	// an assumed-role identity is collapsed to its base IAM role ARN.
	ClaimAssumedRoleArn = "AssumedRoleArn"
	// ClaimRoleSessionName is the (caller-chosen) STS session name, preserved for
	// audit. It does not affect the issued identity.
	ClaimRoleSessionName = "RoleSessionName"
)

// canonicalIdentity derives the single, stable principal identity from the
// attested GetCallerIdentity result.
//
// AWS STS assumed-role sessions
// (arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION) collapse to their base IAM
// role ARN (arn:aws:iam::ACCOUNT:role/ROLE). The STS session name is
// caller-chosen and is not a trustworthy authorization boundary; the IAM role,
// by contrast, is gated by its trust policy. Because AWS role names are unique
// within an account, the base role ARN is a stable, unique identifier for the
// role. The raw assumed-role ARN and session name are preserved in the returned
// claims for audit.
//
// All other identities (IAM users, etc.) are returned unchanged.
//
// Note: the STS assumed-role ARN omits the IAM path for every role, so this
// mapping cannot observe whether a role was created under a non-root path. For a
// pathed role the derived identity is therefore the path-less canonical form
// (arn:aws:iam::ACCOUNT:role/ROLE); register the cloud principal / database user
// using that form.
func canonicalIdentity(arn, account, userID string) (identifier, resourceType string, claims map[string]string) {
	claims = map[string]string{}
	if userID != "" {
		claims[ClaimUserID] = userID
	}

	identifier = arn
	resourceType = arnResourceType(arn)

	if roleName, sessionName, ok := parseAssumedRoleARN(arn); ok {
		identifier = fmt.Sprintf("arn:aws:iam::%s:role/%s", account, roleName)
		resourceType = "role"
		claims[ClaimAssumedRoleArn] = arn
		if sessionName != "" {
			claims[ClaimRoleSessionName] = sessionName
		}
	}

	return identifier, resourceType, claims
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
