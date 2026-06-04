package s2iam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
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

type httpsTestStubProvider struct{}

func (httpsTestStubProvider) Detect(context.Context) error { return nil }
func (httpsTestStubProvider) FastDetect() error            { return nil }
func (httpsTestStubProvider) GetType() models.CloudProviderType {
	return models.ProviderAWS
}
func (p httpsTestStubProvider) AssumeRole(string) models.CloudProviderClient { return p }
func (httpsTestStubProvider) GetIdentityHeaders(context.Context, map[string]string) (map[string]string, *models.CloudIdentity, error) {
	return map[string]string{"X-Stub": "1"}, &models.CloudIdentity{
		Provider:   models.ProviderAWS,
		Identifier: "arn:aws:iam::123456789012:role/test",
	}, nil
}

func TestGetJWT_HTTPURLEnforcement(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"jwt": "header.payload.sig"})
	}))
	t.Cleanup(server.Close)

	serverURL := server.URL + "/auth/iam/:jwtType"
	stub := httpsTestStubProvider{}
	ctx := t.Context()

	t.Run("rejects http without allowHTTP", func(t *testing.T) {
		t.Parallel()
		_, err := GetAPIJWT(ctx, WithServerURL(serverURL), WithProvider(stub))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authentication server URL must use HTTPS")
	})

	t.Run("allows http with allowHTTP", func(t *testing.T) {
		t.Parallel()
		token, err := GetAPIJWT(ctx, WithServerURL(serverURL), WithAllowHTTP(), WithProvider(stub))
		require.NoError(t, err)
		assert.Equal(t, "header.payload.sig", token)
	})
}
