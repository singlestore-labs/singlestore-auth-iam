package aws

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoleSessionNameFromParams(t *testing.T) {
	t.Parallel()

	custom := roleSessionNameFromParams(map[string]string{
		RoleSessionNameParam: "my-custom-session",
	})
	assert.Equal(t, "my-custom-session", custom)

	defaultName := roleSessionNameFromParams(nil)
	assert.True(t, strings.HasPrefix(defaultName, "SingleStoreAuth-"))

	emptyParams := roleSessionNameFromParams(map[string]string{})
	assert.True(t, strings.HasPrefix(emptyParams, "SingleStoreAuth-"))
}
