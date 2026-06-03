package s2iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAuthServerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rawURL    string
		allowHTTP bool
		wantErr   string
	}{
		{
			name:   "https allowed by default",
			rawURL: "https://authsvc.singlestore.com/auth/iam/database",
		},
		{
			name:      "http allowed when opted in",
			rawURL:    "http://localhost:8080/auth/iam/database",
			allowHTTP: true,
		},
		{
			name:    "http rejected by default",
			rawURL:  "http://localhost:8080/auth/iam/database",
			wantErr: "authentication server URL must use HTTPS",
		},
		{
			name:    "unsupported scheme rejected",
			rawURL:  "ftp://example.com/auth/iam/database",
			wantErr: "authentication server URL must use HTTPS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := validateAuthServerURL(tt.rawURL, tt.allowHTTP)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestGetAPIJWT_RejectsHTTPWithoutAllowHTTP(t *testing.T) {
	t.Parallel()

	_, err := GetAPIJWT(t.Context(), WithServerURL("http://localhost:8080/auth/iam/:jwtType"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication server URL must use HTTPS")
}
