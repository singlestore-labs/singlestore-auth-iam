package aws

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/singlestore-labs/singlestore-auth-iam/go/internal/gates"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
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
			name:      "valid GovCloud assumed-role ARN",
			principal: "arn:aws-us-gov:sts::503396375767:assumed-role/NoPermissionsRole/s2iam-session",
			wantErr:   false,
		},
		{
			name:      "valid China partition IAM role ARN",
			principal: "arn:aws-cn:iam::123456789012:role/my-role",
			wantErr:   false,
		},
		{
			name:      "wrong partition prefix rejected",
			principal: "arn:azure:iam::123456789012:role/my-role",
			wantErr:   true,
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

func TestAWSCandidates(t *testing.T) {
	tests := []struct {
		name           string
		arn            string
		account        string
		userID         string
		wantCandidates []models.IdentityCandidate
	}{
		{
			name:    "assumed-role exposes raw ARN, base role ARN, and RoleId",
			arn:     "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session",
			account: "111122223333",
			userID:  "AROAEXAMPLE1234567890:example-session",
			wantCandidates: []models.IdentityCandidate{
				{Format: models.FormatAWSARN, Value: "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session"},
				{Format: models.FormatAWSIAMRoleARN, Value: "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole"},
				{Format: models.FormatAWSRoleID, Value: "AROAEXAMPLE1234567890"},
			},
		},
		{
			name:    "base role ARN and RoleId are session-independent",
			arn:     "arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/i-083dd42864c3524d8",
			account: "503396375767",
			userID:  "AROAXKNGDDTL645XYO7VP:i-083dd42864c3524d8",
			wantCandidates: []models.IdentityCandidate{
				{Format: models.FormatAWSARN, Value: "arn:aws:sts::503396375767:assumed-role/NoPermissionsRole/i-083dd42864c3524d8"},
				{Format: models.FormatAWSIAMRoleARN, Value: "arn:aws:iam::503396375767:role/NoPermissionsRole"},
				{Format: models.FormatAWSRoleID, Value: "AROAXKNGDDTL645XYO7VP"},
			},
		},
		{
			// GovCloud/China: the derived base role ARN keeps the source partition,
			// so it stays byte-identical across the client libraries and this verifier.
			name:    "base role ARN preserves the source partition",
			arn:     "arn:aws-us-gov:sts::503396375767:assumed-role/NoPermissionsRole/s2iam-session",
			account: "503396375767",
			userID:  "AROAXKNGDDTL645XYO7VP:s2iam-session",
			wantCandidates: []models.IdentityCandidate{
				{Format: models.FormatAWSARN, Value: "arn:aws-us-gov:sts::503396375767:assumed-role/NoPermissionsRole/s2iam-session"},
				{Format: models.FormatAWSIAMRoleARN, Value: "arn:aws-us-gov:iam::503396375767:role/NoPermissionsRole"},
				{Format: models.FormatAWSRoleID, Value: "AROAXKNGDDTL645XYO7VP"},
			},
		},
		{
			name:    "IAM user exposes only the raw ARN (always-valid floor)",
			arn:     "arn:aws:iam::123456789012:user/Alice",
			account: "123456789012",
			userID:  "AIDAEXAMPLE",
			wantCandidates: []models.IdentityCandidate{
				{Format: models.FormatAWSARN, Value: "arn:aws:iam::123456789012:user/Alice"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates := awsCandidates(tt.arn, tt.account, tt.userID)
			require.Equal(t, tt.wantCandidates, candidates)
			// The always-valid floor must be the raw caller ARN (aws-arn), which is
			// byte-identical to the historical default.
			require.Equal(t, models.FormatAWSARN, candidates[0].Format)
			require.Equal(t, tt.arn, candidates[0].Value)
		})
	}
}

func TestAWSIdentityClaims(t *testing.T) {
	// Assumed-role sessions preserve the raw ARN, session name, and UserId for
	// audit regardless of which format is negotiated.
	arn := "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session"
	claims := awsIdentityClaims(arn, "AROAEXAMPLE1234567890:example-session")
	require.Equal(t, arn, claims[ClaimAssumedRoleArn])
	require.Equal(t, "example-session", claims[ClaimRoleSessionName])
	require.Equal(t, "AROAEXAMPLE1234567890:example-session", claims[ClaimUserID])

	// IAM users carry only the UserId and no assumed-role alternates.
	userClaims := awsIdentityClaims("arn:aws:iam::123456789012:user/Alice", "AIDAEXAMPLE")
	require.Equal(t, "AIDAEXAMPLE", userClaims[ClaimUserID])
	_, ok := userClaims[ClaimAssumedRoleArn]
	require.False(t, ok, "non-assumed-role identity must not carry AssumedRoleArn claim")
}

// TestVerifierDefaultOrder covers the operator-configured default ordering
// (VerifierConfig.DefaultIdentityFormats, passed through to NewVerifier): it is
// honored when a request carries no preference, and a client preference still
// takes priority over it. VerifyRequest itself needs live STS credentials, so
// this exercises the same composition it performs.
func TestVerifierDefaultOrder(t *testing.T) {
	const (
		callerARN   = "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session"
		account     = "111122223333"
		userID      = "AROAEXAMPLE1234567890:example-session"
		baseRoleARN = "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole"
	)
	candidates := awsCandidates(callerARN, account, userID)

	v, ok := NewVerifier(nil, models.FormatAWSIAMRoleARN, models.FormatAWSARN).(*AWSVerifier)
	require.True(t, ok)

	// No client preference: the configured ordering wins over the built-in default.
	format, identifier := models.SelectIdentityFormat(candidates, nil, v.defaultOrder)
	require.Equal(t, models.FormatAWSIAMRoleARN, format)
	require.Equal(t, baseRoleARN, identifier)

	// A client preference takes priority over the configured ordering.
	format, identifier = models.SelectIdentityFormat(candidates,
		[]models.IdentityFormat{models.FormatAWSARN}, v.defaultOrder)
	require.Equal(t, models.FormatAWSARN, format)
	require.Equal(t, callerARN, identifier)

	// An unconfigured verifier keeps the historical default (the raw caller ARN).
	plain, ok := NewVerifier(nil).(*AWSVerifier)
	require.True(t, ok)
	require.Empty(t, plain.defaultOrder)
	format, identifier = models.SelectIdentityFormat(candidates, nil, plain.defaultOrder)
	require.Equal(t, models.FormatAWSARN, format)
	require.Equal(t, callerARN, identifier)
}
