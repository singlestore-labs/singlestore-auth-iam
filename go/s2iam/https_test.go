package s2iam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

const gateDisabledTestEnv = "S2IAM_REQUIRE_HTTPS_GATE_DISABLED_TEST"

func runWithGateDisabled(t *testing.T, testName string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$", "-test.count=1", "-test.parallel=1")
	cmd.Env = append(os.Environ(), "DISABLE_CODE_S2IAMRequireHTTPS=1", gateDisabledTestEnv+"=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "subprocess output:\n%s", out)
}

func TestValidateAuthServerURL(t *testing.T) {
	t.Parallel()
	require.True(t, gateS2IAMRequireHTTPS.Enabled())

	tests := []struct {
		name      string
		rawURL    string
		allowHTTP bool
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "allows https",
			rawURL:    "https://example.com/auth/iam/api",
			allowHTTP: false,
		},
		{
			name:      "rejects http without allowHTTP",
			rawURL:    "http://example.com/auth/iam/api",
			allowHTTP: false,
			wantErr:   true,
			errSubstr: "authentication server URL must use HTTPS",
		},
		{
			name:      "allows http with allowHTTP",
			rawURL:    "http://example.com/auth/iam/api",
			allowHTTP: true,
		},
		{
			name:      "rejects non-http schemes",
			rawURL:    "ftp://example.com/auth/iam/api",
			allowHTTP: false,
			wantErr:   true,
			errSubstr: "authentication server URL must use HTTPS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := validateAuthServerURL(tt.rawURL, tt.allowHTTP)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateAuthServerURL_GateDisabled(t *testing.T) {
	if os.Getenv(gateDisabledTestEnv) != "1" {
		runWithGateDisabled(t, "TestValidateAuthServerURL_GateDisabled")
		return
	}

	require.False(t, gateS2IAMRequireHTTPS.Enabled())

	_, err := validateAuthServerURL("http://example.com/auth/iam/api", false)
	require.NoError(t, err)

	_, err = validateAuthServerURL("ftp://example.com/auth/iam/api", false)
	require.NoError(t, err)
}

func TestGetJWT_HTTPURLEnforcement(t *testing.T) {
	t.Parallel()
	require.True(t, gateS2IAMRequireHTTPS.Enabled())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"jwt": "header.payload.sig"})
	}))
	t.Cleanup(server.Close)

	serverURL := server.URL + "/auth/iam/:jwtType"
	stub := httpsTestStubProvider{}
	ctx := context.Background()

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

func TestGetJWT_HTTPAllowedWhenGateDisabled(t *testing.T) {
	if os.Getenv(gateDisabledTestEnv) != "1" {
		runWithGateDisabled(t, "TestGetJWT_HTTPAllowedWhenGateDisabled")
		return
	}

	require.False(t, gateS2IAMRequireHTTPS.Enabled())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"jwt": "header.payload.sig"})
	}))
	t.Cleanup(server.Close)

	serverURL := server.URL + "/auth/iam/:jwtType"
	stub := httpsTestStubProvider{}

	token, err := GetAPIJWT(context.Background(), WithServerURL(serverURL), WithProvider(stub))
	require.NoError(t, err)
	assert.Equal(t, "header.payload.sig", token)
}
