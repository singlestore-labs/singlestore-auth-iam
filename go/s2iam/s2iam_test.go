package s2iam_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
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
// If S2IAM_TEST_CLOUD_PROVIDER, S2IAM_TEST_ASSUME_ROLE, or S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE is set, fail instead of skip (test environment should be configured)
func expectCloudProviderDetected(t *testing.T) s2iam.CloudProviderClient {
	if os.Getenv("S2IAM_TEST_CLOUD_PROVIDER") == "" && os.Getenv("S2IAM_TEST_ASSUME_ROLE") == "" && os.Getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") == "" {
		t.Skip("cloud provider required")
	}
	client, err := s2iam.DetectProvider(context.Background(),
		s2iam.WithLogger(t),
		s2iam.WithTimeout(time.Second*5))
	require.NoError(t, err, "cloud provider expected")
	return client
}

// Helper function to require cloud provider with working role/identity (not just detection)
// This is for tests that need to actually use the cloud identity, not just detect the provider
func requireCloudRole(t *testing.T) s2iam.CloudProviderClient {
	if os.Getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") != "" {
		t.Skip("cloud role required")
	}
	return expectCloudProviderDetected(t)
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
				"https://authsvc.singlestore.com",
				"https://authsvc.singlestore.com/auth/iam/database",
				"https://authsvc.singlestore.com/auth/iam/api",
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
func TestGetDatabaseJWT_HappyPath(t *testing.T) {
	t.Parallel()
	client := requireCloudRole(t)

	flags := &fakeServerFlags{requireWorkspaceID: true}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	var token string
	var err error

	// Get client-side identity for comparison
	var clientIdentity *models.CloudIdentity
	if client.GetType() == s2iam.ProviderGCP && (os.Getenv("S2IAM_TEST_CLOUD_PROVIDER") != "" || os.Getenv("S2IAM_TEST_ASSUME_ROLE") != "") {
		// On real GCP, explicitly use the default audience to ensure compatibility
		_, clientIdentity, err = client.GetIdentityHeaders(ctx, map[string]string{"audience": "https://authsvc.singlestore.com"})
		require.NoError(t, err, "Failed to get client-side identity")

		token, err = s2iam.GetDatabaseJWT(ctx, "test-workspace",
			s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"),
			s2iam.WithGCPAudience("https://authsvc.singlestore.com"))
	} else {
		_, clientIdentity, err = client.GetIdentityHeaders(ctx, nil)
		require.NoError(t, err, "Failed to get client-side identity")

		token, err = s2iam.GetDatabaseJWT(ctx, "test-workspace",
			s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"))
	}

	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.Equal(t, 1, flags.requestCount)
	assert.Equal(t, "database", flags.lastJWTType)

	// Verify that client-side and server-side identities match
	require.NotNil(t, clientIdentity, "Client identity should not be nil")
	assert.Equal(t, clientIdentity.Identifier, flags.lastIdentifier,
		"CRITICAL: Client-side identity (%s) differs from server-side identity (%s). This is a security issue!",
		clientIdentity.Identifier, flags.lastIdentifier)

	// Verify the JWT - the sub claim should contain the Identifier (human-readable identity)
	claims := validateJWT(t, token)
	assert.Equal(t, clientIdentity.Identifier, claims["sub"],
		"CRITICAL: Client Identifier (%s) differs from JWT sub claim (%s). The JWT sub claim should match the client identifier!",
		clientIdentity.Identifier, claims["sub"])

	// The Subject is stored in the 'sub' claim of the JWT
	subject, ok := claims["sub"].(string)
	if !ok {
		// Try to handle numeric account IDs (especially for GCP project IDs)
		if numAccountID, numOk := claims["sub"].(float64); numOk {
			subject = fmt.Sprintf("%.0f", numAccountID)
		} else {
			require.Fail(t, "sub claim should be a string or number, got type: %T", claims["sub"])
		}
	}
	require.NotEmpty(t, subject, "sub claim (subject) should not be empty")

	providerType := client.GetType()
	switch providerType {
	case s2iam.ProviderAWS:
		// AWS AccountID should be in ARN format
		awsAccountIDPattern := regexp.MustCompile(`^arn:aws:.*:.*:.*`)
		assert.True(t, awsAccountIDPattern.MatchString(subject),
			"AWS AccountID should be in ARN format, got: %s", subject)
	case s2iam.ProviderGCP:
		// For GCP: Identifier should be email, AccountID should be numeric, JWT sub should be email
		gcpServiceAccountEmailPattern := regexp.MustCompile(`^[a-zA-Z0-9\-_]+@[a-zA-Z0-9\-_]+\.iam\.gserviceaccount\.com$`)
		gcpServiceAccountNumericPattern := regexp.MustCompile(`^\d{10,}$`) // Numeric service account ID (at least 10 digits)

		// Identifier should be email format
		assert.True(t, gcpServiceAccountEmailPattern.MatchString(clientIdentity.Identifier),
			"GCP Identifier should be service account email format, got: %s", clientIdentity.Identifier)

		// AccountID should be numeric
		assert.True(t, gcpServiceAccountNumericPattern.MatchString(clientIdentity.AccountID),
			"GCP AccountID should be numeric service account ID, got: %s", clientIdentity.AccountID)

		// JWT sub claim should match the email identifier (what goes into the JWT)
		assert.Equal(t, clientIdentity.Identifier, subject,
			"GCP JWT sub claim should contain the email identifier, got AccountID: %s, expected Identifier: %s", subject, clientIdentity.Identifier)
	case s2iam.ProviderAzure:
		// Azure AccountID should be subscription ID (UUID format)
		azureSubscriptionPattern := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
		assert.True(t, azureSubscriptionPattern.MatchString(subject),
			"Azure AccountID should be subscription ID (UUID format), got: %s", subject)
	default:
		t.Fatalf("Unknown provider type: %v", providerType)
	}
}

// Test getting API JWT
func TestGetAPIJWT(t *testing.T) {
	t.Parallel()
	client := requireCloudRole(t)

	flags := &fakeServerFlags{}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	var token string
	var err error

	// Handle GCP audience compatibility for real cloud provider testing
	if client.GetType() == s2iam.ProviderGCP && (os.Getenv("S2IAM_TEST_CLOUD_PROVIDER") != "" || os.Getenv("S2IAM_TEST_ASSUME_ROLE") != "") {
		// On real GCP, explicitly use the default audience to ensure compatibility
		token, err = s2iam.GetAPIJWT(ctx,
			s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"),
			s2iam.WithGCPAudience("https://authsvc.singlestore.com"))
	} else {
		token, err = s2iam.GetAPIJWT(ctx,
			s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"))
	}

	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.Equal(t, 1, flags.requestCount)
	assert.Equal(t, "api", flags.lastJWTType)

	// Verify the JWT
	claims := validateJWT(t, token)
	assert.Equal(t, flags.lastIdentifier, claims["sub"])
}

// Test with missing workspace ID
func TestGetDatabaseJWT_MissingWorkspaceID(t *testing.T) {
	t.Parallel()
	_, err := s2iam.GetDatabaseJWT(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workspaceGroupID is required")
}

// Test server returning empty JWT
func TestGetDatabaseJWT_EmptyJWT(t *testing.T) {
	t.Parallel()
	_ = requireCloudRole(t)

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
	t.Parallel()
	_ = requireCloudRole(t)

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
	t.Parallel()
	_ = requireCloudRole(t)

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
	t.Parallel()
	_ = requireCloudRole(t)

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
	t.Parallel()
	client := requireCloudRole(t)

	// Skip if not on GCP
	if client.GetType() != s2iam.ProviderGCP {
		t.Skip("test requires GCP provider")
	}

	// When running on real cloud providers, we can't easily test custom audiences
	// with fake servers because real identity tokens will have specific audiences.
	// For now, just verify that the option doesn't cause an error and that we get a token.
	// The detailed audience verification is tested in unit tests with mock clients.
	if os.Getenv("S2IAM_TEST_CLOUD_PROVIDER") != "" || os.Getenv("S2IAM_TEST_ASSUME_ROLE") != "" {
		// Real cloud test - use a fake server but with the default audience
		flags := &fakeServerFlags{}
		fakeServer := startFakeServer(t, flags)

		ctx := context.Background()
		token, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
			s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"),
			s2iam.WithGCPAudience("https://authsvc.singlestore.com"))
		require.NoError(t, err)
		require.NotEmpty(t, token)
		t.Log("Successfully got JWT with GCP audience option on real cloud provider")
		return
	}

	// Local test with fake server
	flags := &fakeServerFlags{}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	token, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"),
		s2iam.WithGCPAudience("https://test.example.com"))

	require.NoError(t, err)
	require.NotEmpty(t, token)
}

// Test with AssumeRole
func TestGetDatabaseJWT_AssumeRole_Valid(t *testing.T) {
	// Cannot use t.Parallel() - depends on S2IAM_TEST_ASSUME_ROLE environment variable
	// Check for the required environment variable
	roleIdentifier := os.Getenv("S2IAM_TEST_ASSUME_ROLE")
	if roleIdentifier == "" {
		t.Skip("test requires S2IAM_TEST_ASSUME_ROLE environment variable to be set")
	}

	_ = requireCloudRole(t)

	// First, get the original identity without role assumption
	flags := &fakeServerFlags{}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()
	originalJWT, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"))
	require.NoError(t, err)
	originalClaims := validateJWT(t, originalJWT)
	originalIdentifier := originalClaims["sub"].(string)

	// Reset flags for the role assumption test
	flags.requestCount = 0
	flags.lastIdentifier = ""

	// Now test with role assumption
	assumedJWT, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"),
		s2iam.WithAssumeRole(roleIdentifier))

	// Since S2IAM_TEST_ASSUME_ROLE is set, role assumption MUST succeed
	// If it fails, that's a test failure - the environment is misconfigured
	require.NoError(t, err, "AssumeRole must succeed when S2IAM_TEST_ASSUME_ROLE is set. "+
		"Error: %v. This indicates the test environment is not properly configured for role assumption.", err)
	require.NotEmpty(t, assumedJWT)

	// Verify the JWT and check that the identity changed (if role assumption succeeded)
	assumedClaims := validateJWT(t, assumedJWT)
	assumedIdentifier := assumedClaims["sub"].(string)

	// The identifier should have changed to reflect the assumed role
	require.NotEqual(t, originalIdentifier, assumedIdentifier,
		"Identity should change when assuming a role (original: %s, assumed: %s)",
		originalIdentifier, assumedIdentifier)

	// Extract the role name from the role identifier for comparison
	// For AWS: arn:aws:iam::account:role/RoleName -> RoleName
	// For other providers, we'll just use the full identifier
	var expectedRoleName string
	if strings.Contains(roleIdentifier, "arn:aws:iam:") && strings.Contains(roleIdentifier, ":role/") {
		parts := strings.Split(roleIdentifier, ":role/")
		if len(parts) == 2 {
			expectedRoleName = parts[1]
		} else {
			expectedRoleName = roleIdentifier
		}
	} else {
		expectedRoleName = roleIdentifier
	}

	// The assumed identifier should contain the role name
	// For AWS, the assumed role format is: arn:aws:sts::account:assumed-role/RoleName/SessionName
	assert.Contains(t, assumedIdentifier, expectedRoleName,
		"Assumed identity should contain the role name (expected: %s, got: %s)",
		expectedRoleName, assumedIdentifier)

	t.Logf("Successfully assumed role: %s -> %s", originalIdentifier, assumedIdentifier)
}

// Test AssumeRole with invalid role (should fail)
func TestGetDatabaseJWT_AssumeRole_InvalidRole(t *testing.T) {
	t.Parallel()
	client := requireCloudRole(t)

	flags := &fakeServerFlags{}
	fakeServer := startFakeServer(t, flags)

	ctx := context.Background()

	// Generate a properly shaped but non-existent role based on the detected provider
	var invalidRole string
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	switch client.GetType() {
	case s2iam.ProviderAWS:
		invalidRole = fmt.Sprintf("arn:aws:iam::123456789012:role/NonExistentRole-%s", timestamp)
	case s2iam.ProviderGCP:
		invalidRole = fmt.Sprintf("projects/fake-project/serviceAccounts/nonexistent-sa-%s@fake-project.iam.gserviceaccount.com", timestamp)
	case s2iam.ProviderAzure:
		invalidRole = fmt.Sprintf("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/fake-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/nonexistent-identity-%s", timestamp)
	default:
		t.Skipf("test does not support provider type: %s", client.GetType())
	}

	_, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"),
		s2iam.WithAssumeRole(invalidRole))

	// This should fail since the role doesn't exist (or AssumeRole isn't supported)
	require.Error(t, err, "AssumeRole should fail with invalid role")

	// For Azure, we expect the specific "AssumeRole not supported" error
	if client.GetType() == s2iam.ProviderAzure {
		assert.True(t, errors.Is(err, s2iam.ErrAssumeRoleNotSupported),
			"Azure should return ErrAssumeRoleNotSupported, got: %+v", err)
	}

	t.Logf("AssumeRole correctly failed with invalid role (%s format): %s: %v",
		client.GetType(), invalidRole, err)
}

// Test provider detection
func TestDetectProvider(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client, err := s2iam.DetectProvider(ctx, s2iam.WithTimeout(time.Second*5))
	if err != nil {
		// No cloud provider detected - this is expected in some environments
		// unless S2IAM_TEST_CLOUD_PROVIDER or S2IAM_TEST_ASSUME_ROLE is set
		// For S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE, detection failure is acceptable (Azure-style behavior)
		if os.Getenv("S2IAM_TEST_CLOUD_PROVIDER") != "" || os.Getenv("S2IAM_TEST_ASSUME_ROLE") != "" {
			require.NoError(t, err, "cloud provider expected")
		}
		assert.Truef(t, errors.Is(err, s2iam.ErrNoCloudProviderDetected),
			"expected ErrNoCloudProviderDetected, actual error: %+v", err)
		return
	}

	require.NotNil(t, client)
	// Just verify we got a provider, don't check which one to allow for future providers
	providerType := client.GetType()
	require.NotEmpty(t, string(providerType))
}

// Test provider detection with timeout
func TestDetectProvider_Timeout(t *testing.T) {
	t.Parallel()
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
	t.Parallel()

	// Skip this test on no-role hosts since detection may fail
	if os.Getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") != "" {
		t.Skip("test requires working cloud role - skipped on no-role hosts")
	}

	// Get the detected client (or skip if no cloud provider)
	detectedClient := expectCloudProviderDetected(t)

	ctx := context.Background()
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
	_, err := s2iam.DetectProvider(ctx,
		s2iam.WithClients(clients),
		s2iam.WithTimeout(time.Second*2))

	// Should fail since we excluded the actual provider
	require.Error(t, err)
	assert.True(t, errors.Is(err, s2iam.ErrNoCloudProviderDetected),
		"Should return ErrNoCloudProviderDetected when no provider is detected, got: %+v", err)
}

// Test creating verifiers
func TestCreateVerifiers(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	verifiers, err := s2verifier.CreateVerifiers(context.Background(), s2verifier.VerifierConfig{
		Logger: t,
	})
	require.NoError(t, err)

	// Create a request with Azure headers (Bearer token with Azure markers)
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	// Create a fake JWT with Azure-specific claims
	azureToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "https://login.microsoftonline.com/tenant/v2.0",
		"aud": "https://management.azure.com/",
		"sub": "fake-principal-id",
	})
	tokenString, _ := azureToken.SignedString([]byte("fake-secret"))
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
	t.Parallel()
	verifiers, err := s2verifier.CreateVerifiers(context.Background(), s2verifier.VerifierConfig{
		Logger: t,
	})
	require.NoError(t, err)

	// Create a request with no auth headers
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	_, err = verifiers.VerifyRequest(context.Background(), req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, s2verifier.ErrNoValidAuth),
		"Should return ErrNoValidAuth when no auth headers are provided, got: %+v", err)
}

// Test cloud provider with no role assigned (should detect but fail to get identity)
func TestCloudProviderNoRole(t *testing.T) {
	// Cannot use t.Parallel() - depends on S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE environment variable
	// Check if we're testing the no-role scenario
	noRoleProvider := os.Getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
	if noRoleProvider == "" {
		t.Skip("test requires S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE environment variable to be set")
	}

	t.Logf("Testing cloud provider %s with no role assigned", noRoleProvider)

	// Try to detect the cloud provider
	client, err := s2iam.DetectProvider(context.Background(),
		s2iam.WithLogger(t),
		s2iam.WithTimeout(time.Second*5))
	if err != nil {
		// Some providers (like Azure) fail detection when no role is available
		// Others (like AWS) detect the provider but fail when getting identity
		t.Logf("Detection failed as expected: %v", err)

		// Accept either failure mode:
		// 1. ErrNoCloudProviderDetected (Azure-style: fails during detection)
		// 2. ErrProviderDetectedNoIdentity (AWS-style: detects but can't get identity)
		if errors.Is(err, s2iam.ErrNoCloudProviderDetected) || errors.Is(err, s2iam.ErrProviderDetectedNoIdentity) {
			t.Logf("✅ Test passed: Detection correctly failed when no role is assigned")
			return
		}

		assert.Fail(t, "Expected ErrNoCloudProviderDetected or ErrProviderDetectedNoIdentity when no role is assigned, got: %+v", err)
		return
	}

	// Some providers (like AWS) succeed in detection but fail when getting identity
	require.NotNil(t, client)

	// Verify we detected the expected provider
	switch noRoleProvider {
	case "gcp":
		require.Equal(t, s2iam.ProviderGCP, client.GetType())
	case "aws":
		require.Equal(t, s2iam.ProviderAWS, client.GetType())
	case "azure":
		require.Equal(t, s2iam.ProviderAzure, client.GetType())
	default:
		t.Fatalf("Unknown provider in S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE: %s", noRoleProvider)
	}

	t.Logf("Successfully detected %s provider", client.GetType())

	// Getting identity headers should fail due to no role/insufficient permissions
	_, _, err = client.GetIdentityHeaders(context.Background(), nil)
	require.Error(t, err, "GetIdentityHeaders should fail when no role is assigned")

	// The error should be ErrProviderDetectedNoIdentity (provider detected but no identity available)
	t.Logf("Expected error occurred: %v", err)
	assert.True(t, errors.Is(err, s2iam.ErrProviderDetectedNoIdentity),
		"Error should be ErrProviderDetectedNoIdentity when no role is assigned, got: %+v", err)

	t.Logf("✅ Test passed: Detection succeeded but identity retrieval failed as expected")
}

// Test with environment variable for debugging
func TestWithDebugging(t *testing.T) {
	// Cannot use t.Parallel() - modifies global environment variable S2IAM_DEBUGGING
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
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := s2iam.DetectProvider(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

// Test provider with bad metadata endpoint (should timeout quickly)
func TestProvider_BadMetadataEndpoint(t *testing.T) {
	t.Parallel()
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

// Test getting database JWT from production server
func TestGetDatabaseJWT_ProductionServer(t *testing.T) {
	t.Parallel()
	client := requireCloudRole(t)

	// TODO: Production server has audience mismatch for GCP
	// Our GCP client correctly generates tokens with audience "https://authsvc.singlestore.com"
	// but production server only accepts "https://auth.singlestore.com"
	// This should be fixed on the server side to accept both audiences
	//
	// NOTE: Test may show goroutine panic due to parallel detection cleanup - this is a known issue
	// but doesn't affect the test functionality (test correctly skips and passes)
	if client.GetType() == s2iam.ProviderGCP {
		t.Skip("GCP production server test skipped due to audience mismatch - needs server-side fix")
	}

	ctx := context.Background()
	token, err := s2iam.GetDatabaseJWT(ctx, "test-workspace",
		s2iam.WithServerURL("https://authsvc.singlestore.com/auth/iam/:jwtType"))

	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Validate the JWT signature using the production server's JWKS
	err = validateJWTWithProductionJWKS(t, token)
	require.NoError(t, err, "JWT signature validation should succeed")

	t.Log("Successfully got and validated JWT from production server")
}

// validateJWTWithProductionJWKS validates a JWT token using the JWKS from the production server
func validateJWTWithProductionJWKS(t *testing.T, tokenString string) error {
	// Create a JWKS set pointing to the production server's OIDC JWKS endpoint
	jwks, err := jwkset.NewDefaultHTTPClient([]string{"https://authsvc.singlestore.com/auth/oidc/op/Customer/keys"})
	if err != nil {
		return fmt.Errorf("failed to create JWKS client: %v", err)
	}

	// Parse and validate the JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Get the key ID from the token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("JWT header missing 'kid' field")
		}

		// Get the key from the JWKS
		jwk, err := jwks.KeyRead(context.Background(), kid)
		if err != nil {
			return nil, fmt.Errorf("failed to get key from JWKS: %v", err)
		}

		return jwk.Key(), nil
	})
	if err != nil {
		return fmt.Errorf("JWT validation failed: %v", err)
	}

	if !token.Valid {
		return fmt.Errorf("JWT is not valid")
	}

	t.Logf("JWT successfully validated with production JWKS")
	return nil
}
