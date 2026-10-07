package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIdentityFormatPreference(t *testing.T) {
	assert.Nil(t, ParseIdentityFormatPreference(""))
	assert.Equal(t,
		[]IdentityFormat{FormatAWSIAMRoleARN, FormatAWSARN},
		ParseIdentityFormatPreference("aws-iam-role-arn,aws-arn"))
	// Trimming, empty entries dropped, unknown tokens preserved verbatim.
	assert.Equal(t,
		[]IdentityFormat{FormatAWSARN, IdentityFormat("future-token")},
		ParseIdentityFormatPreference(" aws-arn , , future-token "))
}

func TestDefaultIdentityFormats(t *testing.T) {
	// The single flat built-in default ordering spanning providers; the full list
	// is supplied as-is to every verifier (other-provider tokens are harmlessly
	// skipped during negotiation).
	assert.Equal(t, []IdentityFormat{
		FormatAWSARN,
		FormatGCPSAEmail, FormatGCPSAUniqueID,
		FormatAzureObjectID,
	}, DefaultIdentityFormats())
	// A fresh slice each call so callers cannot mutate the shared default.
	a := DefaultIdentityFormats()
	a[0] = FormatAWSIAMRoleARN
	assert.Equal(t, FormatAWSARN, DefaultIdentityFormats()[0])
}

// awsAssumedRoleCandidates are the golden candidate values from the ticket's
// worked example (AWS assumed-role caller).
var awsAssumedRoleCandidates = []IdentityCandidate{
	{Format: FormatAWSARN, Value: "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session"},
	{Format: FormatAWSIAMRoleARN, Value: "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole"},
	{Format: FormatAWSRoleID, Value: "AROAEXAMPLE1234567890"},
}

func TestSelectIdentityFormat_GoldenVectors(t *testing.T) {
	tests := []struct {
		name       string
		valid      []IdentityCandidate
		clientPref []IdentityFormat
		serverDflt []IdentityFormat
		wantFormat IdentityFormat
		wantValue  string
	}{
		{
			name:       "AWS new preference selects base role ARN",
			valid:      awsAssumedRoleCandidates,
			clientPref: []IdentityFormat{FormatAWSIAMRoleARN, FormatAWSARN},
			serverDflt: DefaultIdentityFormats(),
			wantFormat: FormatAWSIAMRoleARN,
			wantValue:  "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole",
		},
		{
			name:       "AWS aws-arn preference selects raw STS ARN (session kept)",
			valid:      awsAssumedRoleCandidates,
			clientPref: []IdentityFormat{FormatAWSARN},
			serverDflt: DefaultIdentityFormats(),
			wantFormat: FormatAWSARN,
			wantValue:  "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session",
		},
		{
			name: "AWS new preference on an IAM user falls back to raw ARN (role token invalid)",
			valid: []IdentityCandidate{
				{Format: FormatAWSARN, Value: "arn:aws:iam::111122223333:user/alice"},
			},
			clientPref: []IdentityFormat{FormatAWSIAMRoleARN, FormatAWSARN},
			serverDflt: DefaultIdentityFormats(),
			wantFormat: FormatAWSARN,
			wantValue:  "arn:aws:iam::111122223333:user/alice",
		},
		{
			name:       "no preference uses server default ordering",
			valid:      awsAssumedRoleCandidates,
			clientPref: nil,
			serverDflt: []IdentityFormat{FormatAWSIAMRoleARN, FormatAWSARN},
			wantFormat: FormatAWSIAMRoleARN,
			wantValue:  "arn:aws:iam::111122223333:role/ExampleCloudPrincipalRole",
		},
		{
			name:  "other-provider and unknown tokens are ignored, default applies",
			valid: awsAssumedRoleCandidates,
			// Non-AWS / unknown tokens simply miss the valid set and are skipped,
			// so the server default applies.
			clientPref: []IdentityFormat{FormatGCPSAEmail, IdentityFormat("future-token")},
			serverDflt: DefaultIdentityFormats(),
			wantFormat: FormatAWSARN,
			wantValue:  "arn:aws:sts::111122223333:assumed-role/ExampleCloudPrincipalRole/example-session",
		},
		{
			name: "empty intersection fails closed to server default then floor",
			// Only the floor is valid (IAM user), but client asked for role formats.
			valid: []IdentityCandidate{
				{Format: FormatAWSARN, Value: "arn:aws:iam::111122223333:user/alice"},
			},
			clientPref: []IdentityFormat{FormatAWSRoleID},
			serverDflt: []IdentityFormat{FormatAWSIAMRoleARN}, // also invalid -> floor
			wantFormat: FormatAWSARN,
			wantValue:  "arn:aws:iam::111122223333:user/alice",
		},
		{
			name: "GCP verified email preferred, numeric is the floor",
			valid: []IdentityCandidate{
				{Format: FormatGCPSAUniqueID, Value: "104561834567890123456"},
				{Format: FormatGCPSAEmail, Value: "my-sa@my-project.iam.gserviceaccount.com"},
			},
			clientPref: nil,
			serverDflt: DefaultIdentityFormats(),
			wantFormat: FormatGCPSAEmail,
			wantValue:  "my-sa@my-project.iam.gserviceaccount.com",
		},
		{
			name: "GCP keeps verified-email default when server default names only AWS",
			valid: []IdentityCandidate{
				{Format: FormatGCPSAUniqueID, Value: "104561834567890123456"},
				{Format: FormatGCPSAEmail, Value: "my-sa@my-project.iam.gserviceaccount.com"},
			},
			clientPref: nil,
			// An AWS-only instance default must not downgrade GCP to the numeric
			// floor: the built-in default is the universal final fallback.
			serverDflt: []IdentityFormat{FormatAWSIAMRoleARN, FormatAWSARN},
			wantFormat: FormatGCPSAEmail,
			wantValue:  "my-sa@my-project.iam.gserviceaccount.com",
		},
		{
			name: "GCP unverified email: only numeric valid, default falls through",
			valid: []IdentityCandidate{
				{Format: FormatGCPSAUniqueID, Value: "104561834567890123456"},
			},
			clientPref: nil,
			serverDflt: DefaultIdentityFormats(),
			wantFormat: FormatGCPSAUniqueID,
			wantValue:  "104561834567890123456",
		},
		{
			name: "Azure user-assigned MI can select resource id",
			valid: []IdentityCandidate{
				{Format: FormatAzureObjectID, Value: "11111111-2222-3333-4444-555555555555"},
				{Format: FormatAzureResourceID, Value: "/subscriptions/SUB/resourcegroups/RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-identity"},
			},
			clientPref: []IdentityFormat{FormatAzureResourceID, FormatAzureObjectID},
			serverDflt: DefaultIdentityFormats(),
			wantFormat: FormatAzureResourceID,
			wantValue:  "/subscriptions/SUB/resourcegroups/RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-identity",
		},
		{
			name: "Azure default keeps object id (sub floor)",
			valid: []IdentityCandidate{
				{Format: FormatAzureObjectID, Value: "11111111-2222-3333-4444-555555555555"},
			},
			clientPref: nil,
			serverDflt: DefaultIdentityFormats(),
			wantFormat: FormatAzureObjectID,
			wantValue:  "11111111-2222-3333-4444-555555555555",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, value := SelectIdentityFormat(tt.valid, tt.clientPref, tt.serverDflt)
			assert.Equal(t, tt.wantFormat, format, "chosen format")
			assert.Equal(t, tt.wantValue, value, "chosen value")
		})
	}
}

func TestSelectIdentityFormat_FloorAlwaysWins(t *testing.T) {
	// Even if client preference, server default, and the valid set share no
	// supported token in common, selection returns the floor (valid[0]).
	valid := []IdentityCandidate{{Format: FormatAWSARN, Value: "arn:aws:iam::1:user/x"}}
	format, value := SelectIdentityFormat(valid,
		[]IdentityFormat{FormatAWSRoleID}, []IdentityFormat{FormatAWSIAMRoleARN})
	require.Equal(t, FormatAWSARN, format)
	require.Equal(t, "arn:aws:iam::1:user/x", value)
}
