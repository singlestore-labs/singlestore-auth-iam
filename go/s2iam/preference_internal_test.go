package s2iam

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

// TestIdentityFormatPreferencePrecedence verifies option > env var > built-in
// default for the identity-format preference sent on the wire.
func TestIdentityFormatPreferencePrecedence(t *testing.T) {
	// The built-in default names every provider so a server-side change to the
	// verifier's default ordering cannot move the issued identity. Each provider's
	// run must end at its always-valid floor for that pinning to be total.
	t.Run("built-in default pins every provider down to its floor", func(t *testing.T) {
		t.Setenv(models.IdentityFormatPreferenceEnv, "")
		var o jwtOptions
		assert.Equal(t, []string{
			"aws-iam-role-arn", "aws-arn",
			"gcp-sa-email", "gcp-sa-unique-id",
			"azure-object-id",
		}, o.identityFormatPreference())
	})

	t.Run("env var overrides the built-in default", func(t *testing.T) {
		t.Setenv(models.IdentityFormatPreferenceEnv, " aws-arn ")
		var o jwtOptions
		assert.Equal(t, []string{"aws-arn"}, o.identityFormatPreference())
	})

	t.Run("explicit option overrides the env var", func(t *testing.T) {
		t.Setenv(models.IdentityFormatPreferenceEnv, "gcp-sa-email")
		o := processJWTOptions(jwtOptions{}, WithIdentityFormatPreference("aws-arn"))
		assert.Equal(t, []string{"aws-arn"}, o.identityFormatPreference())
	})

	t.Run("explicit empty option is honored (sends no preference)", func(t *testing.T) {
		t.Setenv(models.IdentityFormatPreferenceEnv, "gcp-sa-email")
		o := processJWTOptions(jwtOptions{}, WithIdentityFormatPreference())
		assert.Empty(t, o.identityFormatPreference())
	})
}

// TestDefaultPreferencePinsIdentityAgainstServerOverride is the point of sending a
// full, every-provider preference: run the real negotiation for every identity
// shape the verifiers can produce, against a server override that tries to move
// each one, and confirm the client's choice wins every time.
func TestDefaultPreferencePinsIdentityAgainstServerOverride(t *testing.T) {
	clientPref := make([]models.IdentityFormat, 0, len(defaultIdentityFormatPreference))
	for _, f := range defaultIdentityFormatPreference {
		clientPref = append(clientPref, models.IdentityFormat(f))
	}

	// Names a different format for every provider, so any identity that is not
	// pinned by the client preference gets moved.
	hostileOverride := []models.IdentityFormat{
		models.FormatAWSRoleID, models.FormatAWSARN,
		models.FormatGCPSAUniqueID,
		models.FormatAzureResourceID,
	}

	// Candidate sets exactly as the AWS/GCP/Azure verifiers build them (floor first).
	cases := []struct {
		name  string
		valid []models.IdentityCandidate
		want  models.IdentityFormat
	}{
		{
			name: "AWS assumed-role session",
			valid: []models.IdentityCandidate{
				{Format: models.FormatAWSARN, Value: "arn:aws:sts::1:assumed-role/R/S"},
				{Format: models.FormatAWSIAMRoleARN, Value: "arn:aws:iam::1:role/R"},
				{Format: models.FormatAWSRoleID, Value: "AROAEXAMPLE"},
			},
			want: models.FormatAWSIAMRoleARN,
		},
		{
			name:  "AWS IAM user (only the floor is valid)",
			valid: []models.IdentityCandidate{{Format: models.FormatAWSARN, Value: "arn:aws:iam::1:user/alice"}},
			want:  models.FormatAWSARN,
		},
		{
			name: "GCP verified email",
			valid: []models.IdentityCandidate{
				{Format: models.FormatGCPSAUniqueID, Value: "104561834567890123456"},
				{Format: models.FormatGCPSAEmail, Value: "sa@p.iam.gserviceaccount.com"},
			},
			want: models.FormatGCPSAEmail,
		},
		{
			name: "GCP unverified email (only the floor is valid)",
			valid: []models.IdentityCandidate{
				{Format: models.FormatGCPSAUniqueID, Value: "104561834567890123456"},
			},
			want: models.FormatGCPSAUniqueID,
		},
		{
			name: "Azure user-assigned managed identity",
			valid: []models.IdentityCandidate{
				{Format: models.FormatAzureObjectID, Value: "11111111-2222-3333-4444-555555555555"},
				{Format: models.FormatAzureResourceID, Value: "/subscriptions/S/resourcegroups/RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi"},
			},
			want: models.FormatAzureObjectID,
		},
		{
			name: "Azure system-assigned managed identity",
			valid: []models.IdentityCandidate{
				{Format: models.FormatAzureObjectID, Value: "11111111-2222-3333-4444-555555555555"},
			},
			want: models.FormatAzureObjectID,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pinned, _ := models.SelectIdentityFormat(tc.valid, clientPref, hostileOverride)
			assert.Equal(t, tc.want, pinned,
				"the client preference must pin this identity regardless of the server override")

			// Without the client preference the override does move the identity,
			// which is what the full preference list exists to prevent.
			unpinned, _ := models.SelectIdentityFormat(tc.valid, nil, hostileOverride)
			assert.Equal(t, tc.want != unpinned, len(tc.valid) > 1,
				"the override should move exactly those identities with an alternative to move to")
		})
	}
}
