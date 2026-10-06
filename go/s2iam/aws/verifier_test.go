package aws

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/singlestore-labs/singlestore-auth-iam/go/internal/gates"
)

func TestValidatePrincipal(t *testing.T) {
	if !gates.S2IAMValidatePrincipal.Enabled() {
		t.Skip("S2IAMValidatePrincipal gate is disabled")
	}

	tests := []struct {
		name      string
		principal string
		wantErr   bool
	}{
		{
			name:      "valid IAM role ARN",
			principal: "arn:aws:iam::123456789012:role/my-role",
			wantErr:   false,
		},
		{
			name:      "valid STS assumed-role ARN",
			principal: "arn:aws:sts::123456789012:assumed-role/my-role/session",
			wantErr:   false,
		},
		{
			name:      "empty principal",
			principal: "",
			wantErr:   true,
		},
		{
			name:      "non-ARN principal",
			principal: "not-an-arn",
			wantErr:   true,
		},
		{
			name:      "invalid account ID length",
			principal: "arn:aws:iam::12345:role/my-role",
			wantErr:   true,
		},
		{
			name:      "missing resource segment",
			principal: "arn:aws:iam::123456789012:",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePrincipal(tt.principal)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestCanonicalIdentity(t *testing.T) {
	tests := []struct {
		name            string
		arn             string
		account         string
		userID          string
		wantIdentifier  string
		wantResource    string
		wantAssumedRole string // expected AssumedRoleArn claim ("" means absent)
		wantSession     string // expected RoleSessionName claim ("" means absent)
	}{
		{
			name:            "assumed-role collapses to base role ARN",
			arn:             "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session",
			account:         "111122223333",
			userID:          "AROAEXAMPLE1234567890:example-session",
			wantIdentifier:  "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole",
			wantResource:    "role",
			wantAssumedRole: "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session",
			wantSession:     "example-session",
		},
		{
			name:            "session name does not affect identity",
			arn:             "arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/s2iam-session",
			account:         "503396375767",
			userID:          "AROAXKNGDDTLTYVC4AL2R:s2iam-session",
			wantIdentifier:  "arn:aws:iam::503396375767:role/NoPermissionsRole",
			wantResource:    "role",
			wantAssumedRole: "arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/s2iam-session",
			wantSession:     "s2iam-session",
		},
		{
			name:           "instance-profile session collapses to role",
			arn:            "arn:aws:sts::503396375767:assumed-role/AllowAssumeNoPermissionsRole/i-083dd42864c3524d8",
			account:        "503396375767",
			userID:         "AROAXKNGDDTL645XYO7VP:i-083dd42864c3524d8",
			wantIdentifier: "arn:aws:iam::503396375767:role/AllowAssumeNoPermissionsRole",
			wantResource:   "role",
			// session (instance id) preserved as a claim but not asserted here
			wantAssumedRole: "arn:aws:sts::503396375767:assumed-role/AllowAssumeNoPermissionsRole/i-083dd42864c3524d8",
			wantSession:     "i-083dd42864c3524d8",
		},
		{
			name:           "IAM user is returned unchanged",
			arn:            "arn:aws:iam::123456789012:user/Alice",
			account:        "123456789012",
			userID:         "AIDAEXAMPLE",
			wantIdentifier: "arn:aws:iam::123456789012:user/Alice",
			wantResource:   "user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identifier, resourceType, claims := canonicalIdentity(tt.arn, tt.account, tt.userID)
			require.Equal(t, tt.wantIdentifier, identifier)
			require.Equal(t, tt.wantResource, resourceType)
			if tt.userID != "" {
				require.Equal(t, tt.userID, claims[ClaimUserID])
			}
			if tt.wantAssumedRole != "" {
				require.Equal(t, tt.wantAssumedRole, claims[ClaimAssumedRoleArn])
			} else {
				_, ok := claims[ClaimAssumedRoleArn]
				require.False(t, ok, "non-assumed-role identity must not carry AssumedRoleArn claim")
			}
			if tt.wantSession != "" {
				require.Equal(t, tt.wantSession, claims[ClaimRoleSessionName])
			}
		})
	}
}
