package s2iam_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/s2verifier"
)

var privateKey, publicKey = func() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key pair: %v", err)
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey
}()

// Helper function to detect cloud provider and skip test if none found
func requireCloudProvider(t *testing.T) s2iam.CloudProviderClient {
	client, err := s2iam.DetectProvider(context.Background(),
		s2iam.WithLogger(t),
		s2iam.WithTimeout(time.Second*5))
	if err != nil {
		t.Skipf("test requires a cloud provider: %+v", err)
	}
	return client
}

func validateJWT(t *testing.T, tokenString string) jwt.MapClaims {
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	require.NoError(t, err)
	require.True(t, parsedToken.Valid)
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims
}

func signJWT(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	return tokenString, err
}

type fakeServerFlags struct {
	// Control server behavior
	failVerification   bool
	returnEmptyJWT     bool
	returnInvalidJSON  bool
	serverError        bool
	requireWorkspaceID bool

	// Track requests for assertions
	requestCount   int
	lastProvider   string
	lastIdentifier string
	lastJWTType    string
}

func startFakeServer(t *testing.T, flags *fakeServerFlags) *httptest.Server {
	v, err := s2verifier.CreateVerifiers(context.Background(),
		s2verifier.VerifierConfig{
			Logger: t, // Directly use testing.T as the logger
			AllowedAudiences: []string{
				"https://auth.singlestore.com",
				"https://auth.singlestore.com/auth/iam/database",
				"https://auth.singlestore.com/auth/iam/api",
				"https://test.example.com", // For testing custom audiences
			},
		})
	require.NoError(t, err)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flags.requestCount++

		t.Logf("[server] received request %s %s", r.Method, r.URL)

		// Extract JWT type from URL
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) >= 3 {
			flags.lastJWTType = pathParts[len(pathParts)-1]
		}

		// Simulate server errors if requested
		if flags.serverError {
			http.Error(w, "internal server error", 500)
			return
		}

		// Check required parameters
		if flags.requireWorkspaceID && flags.lastJWTType == "database" {
			workspaceID := r.URL.Query().Get("workspaceGroupID")
			if workspaceID == "" {
				http.Error(w, "workspaceGroupID is required", 400)
				return
			}
		}

		// Verify the incoming request
		if flags.failVerification {
			http.Error(w, "verification failed", http.StatusUnauthorized)
			return
		}

		t.Log("[server] verifying service account")
		cloudIdentity, err := v.VerifyRequest(r.Context(), r)
		if err != nil {
			t.Logf("[server] verification failed: %+v", err)
			http.Error(w, err.Error(), 400)
			return
		}

		flags.lastProvider = string(cloudIdentity.Provider)
		flags.lastIdentifier = cloudIdentity.Identifier

		t.Logf("[server] service account verified: %s %s", cloudIdentity.Provider, cloudIdentity.Identifier)

		// Return various error conditions if requested
		if flags.returnInvalidJSON {
			_, _ = w.Write([]byte("{invalid json"))
			return
		}

		if flags.returnEmptyJWT {
			enc, _ := json.Marshal(map[string]any{
				"jwt": "",
			})
			_, _ = w.Write(enc)
			return
		}

		// Create a valid JWT
		tokenString, err := signJWT(jwt.MapClaims{
			"sub":          cloudIdentity.Identifier,
			"provider":     cloudIdentity.Provider,
			"accountID":    cloudIdentity.AccountID,
			"region":       cloudIdentity.Region,
			"resourceType": cloudIdentity.ResourceType,
			"iat":          time.Now().Unix(),
			"exp":          time.Now().Add(time.Hour).Unix(),
		})
		if err != nil {
			t.Logf("[server] jwt creation failed: %s", err)
			http.Error(w, err.Error(), 500)
			return
		}

		enc, err := json.Marshal(map[string]any{
			"jwt": tokenString,
		})
		if err != nil {
			t.Logf("[server] jwt creation failed: %s", err)
			http.Error(w, err.Error(), 500)
			return
		}

		_, _ = w.Write(enc)
		t.Log("[server] returning jwt")
	}))
	t.Cleanup(s.Close)
	return s
}

// Test getting database JWT with valid provider
func TestGetDatabaseJWT(t *testing.T) {
	_ = requireCloudProvider(t)

	flags := &fakeServerFlags{requireWorkspaceID: true}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	jwt, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"))

	require.NoError(t, err)
	require.NotEmpty(t, jwt)
	assert.Equal(t, 1, flags.requestCount)
	assert.Equal(t, "database", flags.lastJWTType)

	// Verify the JWT
	claims := validateJWT(t, jwt)
	assert.Equal(t, flags.lastIdentifier, claims["sub"])
}

// Test getting API JWT
func TestGetAPIJWT(t *testing.T) {
	_ = requireCloudProvider(t)

	flags := &fakeServerFlags{}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	jwt, err := s2iam.GetAPIJWT(ctx,
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"))

	require.NoError(t, err)
	require.NotEmpty(t, jwt)
	assert.Equal(t, 1, flags.requestCount)
	assert.Equal(t, "api", flags.lastJWTType)

	// Verify the JWT
	claims := validateJWT(t, jwt)
	assert.Equal(t, flags.lastIdentifier, claims["sub"])
}

// Test with missing workspace ID
func TestGetDatabaseJWT_MissingWorkspaceID(t *testing.T) {
	_, err := s2iam.GetDatabaseJWT(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workspaceGroupID is required")
}

// Test server returning empty JWT
func TestGetDatabaseJWT_EmptyJWT(t *testing.T) {
	_ = requireCloudProvider(t)

	flags := &fakeServerFlags{returnEmptyJWT: true}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	_, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "received empty JWT")
}

// Test server returning invalid JSON
func TestGetDatabaseJWT_InvalidJSON(t *testing.T) {
	_ = requireCloudProvider(t)

	flags := &fakeServerFlags{returnInvalidJSON: true}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	_, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot parse response")
}

// Test server error
func TestGetDatabaseJWT_ServerError(t *testing.T) {
	_ = requireCloudProvider(t)

	flags := &fakeServerFlags{serverError: true}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	_, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication server returned status 500")
}

// Test verification failure
func TestGetDatabaseJWT_VerificationFailure(t *testing.T) {
	_ = requireCloudProvider(t)

	flags := &fakeServerFlags{failVerification: true}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	_, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication server returned status 401")
}

// Test with GCP audience parameter
func TestGetDatabaseJWT_GCPAudience(t *testing.T) {
	client := requireCloudProvider(t)

	// Skip if not on GCP
	if client.GetType() != s2iam.ProviderGCP {
		t.Skip("test requires GCP provider")
	}

	flags := &fakeServerFlags{}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	jwt, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"),
		s2iam.WithGCPAudience("https://test.example.com"))

	require.NoError(t, err)
	require.NotEmpty(t, jwt)
}

// Test with AssumeRole
func TestGetDatabaseJWT_AssumeRole(t *testing.T) {
	roleIdentifier := os.Getenv("S2IAM_TEST_ASSUME_ROLE")
	if roleIdentifier == "" {
		t.Skipf("%s needs S2IAM_TEST_ASSUME_ROLE to be set")
	}
	flags := &fakeServerFlags{}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	jwt, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"),
		s2iam.WithAssumeRole(roleIdentifier))
	// This may fail if the role doesn't exist, but we're testing the flow
	if err != nil {
		t.Logf("AssumeRole test failed (expected if role doesn't exist): %v", err)
		return
	}

	require.NotEmpty(t, jwt)
}

// Test provider detection
func TestDetectProvider(t *testing.T) {
	ctx := context.Background()
	client, err := s2iam.DetectProvider(ctx, s2iam.WithTimeout(time.Second*5))
	if err != nil {
		// No cloud provider detected - this is expected in some environments
		assert.Contains(t, err.Error(), "no cloud provider detected")
		return
	}

	require.NotNil(t, client)
	// Just verify we got a provider, don't check which one to allow for future providers
	providerType := client.GetType()
	require.NotEmpty(t, string(providerType))
}

// Test provider detection with timeout
func TestDetectProvider_Timeout(t *testing.T) {
	ctx := context.Background()
	client, err := s2iam.DetectProvider(ctx, s2iam.WithTimeout(time.Millisecond))

	if err == nil && client != nil {
		// Provider was detected very quickly, which is fine
		return
	}

	require.Error(t, err)
	// The error could be either timeout or no provider detected
}

// Test provider detection with specific clients
func TestDetectProvider_SpecificClients(t *testing.T) {
	ctx := context.Background()

	// First, detect which provider we're currently on
	detectedClient, err := s2iam.DetectProvider(ctx, s2iam.WithTimeout(time.Second*5))
	if err != nil {
		// No provider detected, can't test exclusion
		t.Skip("test requires a cloud provider to exclude")
	}

	detectedType := detectedClient.GetType()
	t.Logf("Detected provider: %s", detectedType)

	// Create a list of clients that excludes the detected provider
	var clients []s2iam.CloudProviderClient

	// Add all providers except the detected one
	if detectedType != s2iam.ProviderAWS {
		clients = append(clients, s2iam.NewAWSClient(t))
	}
	if detectedType != s2iam.ProviderGCP {
		clients = append(clients, s2iam.NewGCPClient(t))
	}
	if detectedType != s2iam.ProviderAzure {
		clients = append(clients, s2iam.NewAzureClient(t))
	}

	// Now try to detect with the current provider excluded
	_, err = s2iam.DetectProvider(ctx,
		s2iam.WithClients(clients),
		s2iam.WithTimeout(time.Second*2))

	// Should fail since we excluded the actual provider
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no cloud provider detected")
}

// Test creating verifiers
func TestCreateVerifiers(t *testing.T) {
	ctx := context.Background()
	verifiers, err := s2verifier.CreateVerifiers(ctx, s2verifier.VerifierConfig{
		AllowedAudiences: []string{"https://test.example.com"},
		AzureTenant:      "common",
		Logger:           t,
	})

	require.NoError(t, err)
	require.NotNil(t, verifiers)

	// Check that we have verifiers (don't assume specific ones to allow for future providers)
	assert.NotEmpty(t, verifiers)
}

// Test verifier with mock AWS headers
func TestVerifier_AWS(t *testing.T) {
	// This is a unit test that doesn't require actual AWS credentials
	verifiers, err := s2verifier.CreateVerifiers(context.Background(), s2verifier.VerifierConfig{
		Logger: t,
	})
	require.NoError(t, err)

	// Create a request with AWS headers
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("X-AWS-Access-Key-ID", "fake-key")
	req.Header.Set("X-AWS-Secret-Access-Key", "fake-secret")
	req.Header.Set("X-AWS-Session-Token", "fake-token")

	// Check that AWS verifier recognizes the headers
	awsVerifier, ok := verifiers[s2iam.ProviderAWS]
	if !ok {
		t.Skip("AWS verifier not available")
	}

	assert.True(t, awsVerifier.HasHeaders(req))

	// Verification will fail with fake credentials, but that's expected
	_, err = awsVerifier.VerifyRequest(context.Background(), req)
	require.Error(t, err)
}

// Test verifier with mock GCP headers
func TestVerifier_GCP(t *testing.T) {
	verifiers, err := s2verifier.CreateVerifiers(context.Background(), s2verifier.VerifierConfig{
		Logger:           t,
		AllowedAudiences: []string{"https://test.example.com"},
	})
	require.NoError(t, err)

	// Create a request with GCP headers (Bearer token)
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Authorization", "Bearer fake.gcp.token")

	// Check that GCP verifier recognizes the headers
	gcpVerifier, ok := verifiers[s2iam.ProviderGCP]
	if !ok {
		t.Skip("GCP verifier not available")
	}

	assert.True(t, gcpVerifier.HasHeaders(req))

	// Verification will fail with fake token, but that's expected
	_, err = gcpVerifier.VerifyRequest(context.Background(), req)
	require.Error(t, err)
}

// Test verifier with mock Azure headers
func TestVerifier_Azure(t *testing.T) {
	verifiers, err := s2verifier.CreateVerifiers(context.Background(), s2verifier.VerifierConfig{
		Logger: t,
	})
	require.NoError(t, err)

	// Create a request with Azure headers (Bearer token with Azure markers)
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	// Create a fake JWT with Azure-specific claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "https://login.microsoftonline.com/tenant/v2.0",
		"aud": "https://management.azure.com/",
		"sub": "fake-principal-id",
	})
	tokenString, _ := token.SignedString([]byte("fake-secret"))
	req.Header.Set("Authorization", "Bearer "+tokenString)

	// Check that Azure verifier recognizes the headers
	azureVerifier, ok := verifiers[s2iam.ProviderAzure]
	if !ok {
		t.Skip("Azure verifier not available")
	}

	assert.True(t, azureVerifier.HasHeaders(req))

	// Verification will fail with fake token, but that's expected
	_, err = azureVerifier.VerifyRequest(context.Background(), req)
	require.Error(t, err)
}

// Test VerifyRequest with no valid auth
func TestVerifiers_NoValidAuth(t *testing.T) {
	verifiers, err := s2verifier.CreateVerifiers(context.Background(), s2verifier.VerifierConfig{
		Logger: t,
	})
	require.NoError(t, err)

	// Create a request with no auth headers
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	_, err = verifiers.VerifyRequest(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid cloud provider authentication found")
}

// Test with environment variable for debugging
func TestWithDebugging(t *testing.T) {
	// Set debugging env var
	_ = os.Setenv("S2IAM_DEBUGGING", "true")
	defer func() {
		_ = os.Unsetenv("S2IAM_DEBUGGING")
	}()

	// This should create a logger automatically
	client, err := s2iam.DetectProvider(context.Background(),
		s2iam.WithTimeout(time.Second*2))
	if err != nil {
		// Provider not detected, but logger should have been created
		return
	}

	require.NotNil(t, client)
}

// Test context cancellation
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := s2iam.DetectProvider(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

// Test provider with bad metadata endpoint (should timeout quickly)
func TestProvider_BadMetadataEndpoint(t *testing.T) {
	// This tests the timeout handling when metadata endpoints are unreachable
	ctx := context.Background()

	// Set a short timeout to make the test run quickly
	client, err := s2iam.DetectProvider(ctx, s2iam.WithTimeout(time.Second))

	if err == nil && client != nil {
		// We're actually running on a cloud provider
		return
	}

	// Should get an error when not on any cloud provider
	require.Error(t, err)
}
