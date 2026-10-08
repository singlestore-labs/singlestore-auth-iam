package s2iam

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

// TestIdentityFormatPreferencePrecedence verifies option > env var > built-in
// default for the identity-format preference sent on the wire.
func TestIdentityFormatPreferencePrecedence(t *testing.T) {
	t.Run("built-in default is the raw AWS ARN", func(t *testing.T) {
		t.Setenv(models.IdentityFormatPreferenceEnv, "")
		var o jwtOptions
		assert.Equal(t, []string{string(models.FormatAWSARN)}, o.identityFormatPreference())
	})

	t.Run("env var overrides the built-in default", func(t *testing.T) {
		t.Setenv(models.IdentityFormatPreferenceEnv, " aws-iam-role-arn , aws-arn ")
		var o jwtOptions
		assert.Equal(t, []string{"aws-iam-role-arn", "aws-arn"}, o.identityFormatPreference())
	})

	t.Run("explicit option overrides the env var", func(t *testing.T) {
		t.Setenv(models.IdentityFormatPreferenceEnv, "gcp-sa-email")
		o := processJWTOptions(jwtOptions{}, WithIdentityFormatPreference("aws-iam-role-arn", "aws-arn"))
		assert.Equal(t, []string{"aws-iam-role-arn", "aws-arn"}, o.identityFormatPreference())
	})

	t.Run("explicit empty option is honored (sends no preference)", func(t *testing.T) {
		t.Setenv(models.IdentityFormatPreferenceEnv, "gcp-sa-email")
		o := processJWTOptions(jwtOptions{}, WithIdentityFormatPreference())
		assert.Empty(t, o.identityFormatPreference())
	})
}
