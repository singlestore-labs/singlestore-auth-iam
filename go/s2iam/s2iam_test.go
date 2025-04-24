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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/verifier"
)

var privateKey, publicKey = func() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key pair: %v", err)
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey
}()

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

func determineCurrentCloudProvider(t *testing.T) string {
	t.Helper()

	if os.Getenv("AWS_EXECUTION_ENV") != "" {
		return "aws"
	}
	if os.Getenv("GCE_METADATA_HOST") != "" {
		return "gcp"
	}
	if os.Getenv("AZURE_ENV") != "" {
		return "azure"
	}
	return "none"
}

type fakeServerFlags struct{}

func startFakeServer(t *testing.T, flags fakeServerFlags) *httptest.Server {
	v, err := verifier.NewVerifier(context.Background(),
		verifier.VerifierConfig{})
	require.NoError(t, err)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("[server] received request %s %s", r.Method, r.URL)
		t.Log("[server] verifying service account")
		cloudIdentity, err := v.VerifyRequest(r.Context(), r)
		if err != nil {
			t.Logf("[server] verification failed: %s", err)
			http.Error(w, err.Error(), 400)
			return
		}
		t.Logf("[server] service account verified: %s %s", cloudIdentity.Provider, cloudIdentity.Identifier)
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
		return
	}))
	t.Cleanup(s.Close)
	return s
}

func TestGetDatabaseTestServerJWT(t *testing.T) {
	if determineCurrentCloudProvider(t) == "none" {
		t.Skip("test requires a cloud provider")
	}
	fakeServer := startFakeServer(t, fakeServerFlags{})
	ctx := context.Background()
	jwt, err := s2iam.GetDatabaseJWT(ctx, "fake-workspace", s2iam.WithExternalServerURL(fakeServer.URL+"/iam/:jwtType"))
	require.NoError(t, err)
	require.NotEmpty(t, jwt)
	validateJWT(t, jwt)
}

/*

// MockCloudVerifier is a mock implementation of the CloudVerifier interface
type MockCloudVerifier struct {
	mock.Mock
}

// VerifyRequest implements the CloudVerifier interface
func (m *MockCloudVerifier) VerifyRequest(ctx context.Context, r *http.Request) (*verifier.CloudIdentity, error) {
	args := m.Called(ctx, r)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*verifier.CloudIdentity), args.Error(1)
}

// setupTestServer creates a mock HTTP server for testing
func setupTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// createMockAuthServer creates a test server that fully validates incoming requests
// and returns appropriate JWT responses regardless of which cloud provider it's running on
func createMockAuthServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Helper()

		// Validate HTTP method
		if r.Method != http.MethodPost {
			t.Logf("Invalid method: %s", r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract JWT type and validate path
		var jwtType string
		if strings.Contains(r.URL.Path, "database") {
			jwtType = "database"
		} else if strings.Contains(r.URL.Path, "api") {
			jwtType = "api"
		} else {
			t.Logf("Invalid path: %s", r.URL.Path)
			http.Error(w, "Invalid JWT type in path", http.StatusBadRequest)
			return
		}

		// For database JWT requests, verify workspaceGroupID is present
		if jwtType == "database" && r.URL.Query().Get("workspaceGroupID") == "" {
			t.Log("Missing workspaceGroupID for database request")
			http.Error(w, "Missing workspaceGroupID", http.StatusBadRequest)
			return
		}

		// Handle authentication headers
		provider := determineProviderFromHeaders(r, t)
		if provider == "" {
			t.Log("No valid authentication headers found")
			http.Error(w, "No valid authentication headers", http.StatusUnauthorized)
			return
		}

		// Send response with appropriate JWT
		sendJWTResponse(w, provider)
	}))
}

// determineProviderFromHeaders determines the cloud provider based on headers
func determineProviderFromHeaders(r *http.Request, t *testing.T) string {
	t.Helper()

	// Check for AWS headers
	if r.Header.Get("X-AWS-Access-Key-ID") != "" {
		if r.Header.Get("X-AWS-Secret-Access-Key") == "" || r.Header.Get("X-AWS-Session-Token") == "" {
			t.Log("Incomplete AWS headers")
			return ""
		}
		return "aws"
	}

	// Check for GCP/Azure bearer token
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			t.Log("Empty bearer token")
			return ""
		}

		// Determine provider based on token format (simplified for testing)
		if len(token) > 100 {
			return "gcp"
		}
		return "azure"
	}

	return ""
}

// sendJWTResponse sends a mock JWT response
func sendJWTResponse(w http.ResponseWriter, provider string) {
	response := struct {
		JWT string `json:"jwt"`
	}{
		JWT: fmt.Sprintf("mock.%s.jwt.token.%s", provider, time.Now().Format(time.RFC3339)),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// setupMockExternalServer creates a mock server for testing JWT retrieval
func setupMockExternalServer(t *testing.T) *httptest.Server {
	return setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Helper()

		cloudProvider := r.Header.Get("X-Test-Cloud-Provider")
		if cloudProvider == "" {
			cloudProvider = "mock"
		}

		response := struct {
			JWT string `json:"jwt"`
		}{
			JWT: fmt.Sprintf("mock.%s.jwt.%s", cloudProvider, time.Now().Format(time.RFC3339)),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})
}

// setupMockMetadataServers sets up mock servers for cloud provider metadata services
func setupMockMetadataServers(t *testing.T) (awsServer, gcpServer, azureServer *httptest.Server, cleanupFn func()) {
	t.Helper()

	// Mock AWS metadata server
	awsServer = setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/latest/meta-data/")

		switch path {
		case "instance-id":
			fmt.Fprintln(w, "i-1234567890abcdef0")
		case "iam/info":
			fmt.Fprintf(w, `{"Code":"Success","LastUpdated":"2023-04-14T12:00:00Z","InstanceProfileArn":"arn:aws:iam::123456789012:instance-profile/test-role","InstanceProfileId":"AIPAJCJEDLZS2XAMPLE"}`)
		case "iam/security-credentials/":
			fmt.Fprintln(w, "test-role")
		case "iam/security-credentials/test-role":
			fmt.Fprintf(w, `{
				"Code": "Success",
				"LastUpdated": "2023-04-14T12:00:00Z",
				"Type": "AWS-HMAC",
				"AccessKeyId": "ASIAJEXAMPLEKEY",
				"SecretAccessKey": "EXAMPLESECRETKEY",
				"Token": "EXAMPLETOKEN",
				"Expiration": "2023-04-15T06:00:00Z"
			}`)
		default:
			http.NotFound(w, r)
		}
	})

	// Mock GCP metadata server
	gcpServer = setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "Missing Metadata-Flavor header", http.StatusBadRequest)
			return
		}

		if strings.Contains(r.URL.Path, "instance/service-accounts/default/identity") {
			audience := r.URL.Query().Get("audience")
			if audience == "" {
				http.Error(w, "Missing audience", http.StatusBadRequest)
				return
			}
			// Mock GCP identity token
			fmt.Fprintf(w, "gcp-mock-identity-token-for-%s", audience)
			return
		}

		if strings.Contains(r.URL.Path, "instance/service-accounts/default/token") {
			// Mock GCP access token
			fmt.Fprintf(w, `{
				"access_token": "mock-gcp-access-token",
				"expires_in": 3600,
				"token_type": "Bearer"
			}`)
			return
		}

		http.NotFound(w, r)
	})

	// Mock Azure metadata server
	azureServer = setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			http.Error(w, "Missing Metadata header", http.StatusBadRequest)
			return
		}

		apiVersion := r.URL.Query().Get("api-version")
		resource := r.URL.Query().Get("resource")
		clientID := r.URL.Query().Get("client_id")

		if apiVersion == "" || resource == "" {
			http.Error(w, "Missing required parameters", http.StatusBadRequest)
			return
		}

		// Mock response
		response := struct {
			AccessToken  string `json:"access_token"`
			ClientID     string `json:"client_id,omitempty"`
			ExpiresIn    int    `json:"expires_in"`
			ExpiresOn    int    `json:"expires_on"`
			ExtExpiresIn int    `json:"ext_expires_in"`
			NotBefore    int    `json:"not_before"`
			Resource     string `json:"resource"`
			TokenType    string `json:"token_type"`
		}{
			AccessToken:  "mock-azure-access-token",
			ClientID:     clientID,
			ExpiresIn:    3600,
			ExpiresOn:    int(time.Now().Unix()) + 3600,
			ExtExpiresIn: 3600,
			NotBefore:    int(time.Now().Unix()),
			Resource:     resource,
			TokenType:    "Bearer",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Return cleanup function
	cleanupFn = func() {
		awsServer.Close()
		gcpServer.Close()
		azureServer.Close()
	}

	return awsServer, gcpServer, azureServer, cleanupFn
}

// TestWithOptions tests the option configuration functions
func TestWithOptions(t *testing.T) {
	t.Parallel()

	t.Run("WithExternalServerURL", func(t *testing.T) {
		t.Parallel()
		options := jwtOptions{}
		customURL := "https://custom.auth.server.com"
		WithExternalServerURL(customURL)(&options)
		assert.Equal(t, customURL, options.ExternalServerURL)
	})

	t.Run("WithGCPAudience", func(t *testing.T) {
		t.Parallel()
		options := jwtOptions{}
		customAudience := "https://custom.audience.com"
		WithGCPAudience(customAudience)(&options)
		assert.Equal(t, customAudience, options.GCPAudience)
	})

	t.Run("WithAssumeRole", func(t *testing.T) {
		t.Parallel()
		options := jwtOptions{}
		roleARN := "arn:aws:iam::123456789012:role/test-role"
		WithAssumeRole(roleARN)(&options)
		assert.Equal(t, roleARN, options.AssumeRoleIdentifier)
	})

	t.Run("Multiple options", func(t *testing.T) {
		t.Parallel()
		options := jwtOptions{
			JWTType:          DatabaseAccessJWT,
			WorkspaceGroupID: "test-group",
		}

		// Apply multiple options
		customURL := "https://custom.auth.server.com"
		customAudience := "https://custom.audience.com"
		roleARN := "arn:aws:iam::123456789012:role/test-role"

		// Apply options
		funcs := []JWTOption{
			WithExternalServerURL(customURL),
			WithGCPAudience(customAudience),
			WithAssumeRole(roleARN),
		}

		for _, opt := range funcs {
			opt(&options)
		}

		// Verify options were applied
		assert.Equal(t, customURL, options.ExternalServerURL)
		assert.Equal(t, customAudience, options.GCPAudience)
		assert.Equal(t, roleARN, options.AssumeRoleIdentifier)

		// Verify original fields are preserved
		assert.Equal(t, DatabaseAccessJWT, options.JWTType)
		assert.Equal(t, "test-group", options.WorkspaceGroupID)
	})
}

// TestDatabaseJWTValidation tests validation of database JWT parameters
func TestDatabaseJWTValidation(t *testing.T) {
	t.Parallel()

	t.Run("Missing workspace group ID", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		_, err := GetDatabaseJWT(ctx, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "workspaceGroupID is required")
	})

	t.Run("Missing external server URL", func(t *testing.T) {
		t.Parallel()

		// Save original function to restore later
		originalGetJWT := getJWT
		defer func() { getJWT = originalGetJWT }()

		// Mock getJWT to check options
		getJWT = func(ctx context.Context, options jwtOptions) (string, error) {
			if options.ExternalServerURL == "" {
				return "", errors.New("external server URL is required")
			}
			return "mock.jwt", nil
		}

		// Override ExternalServerURL with empty string
		ctx := context.Background()
		_, err := GetDatabaseJWT(ctx, "test-group", WithExternalServerURL(""))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "external server URL is required")
	})
}

// TestAWSIdentityHeaders tests AWS identity header generation
func TestAWSIdentityHeaders(t *testing.T) {
	cloudProvider := determineCurrentCloudProvider(t)

	t.Run("AWS identity headers in AWS environment", func(t *testing.T) {
		if cloudProvider != "aws" {
			t.Skip("Skipping AWS test in non-AWS environment")
		}

		t.Parallel()
		ctx := context.Background()

		headers, provider, err := getAWSIdentityHeaders(ctx, "")
		require.NoError(t, err)
		assert.Equal(t, "aws", provider)
		assert.Contains(t, headers, "X-AWS-Access-Key-ID")
		assert.Contains(t, headers, "X-AWS-Secret-Access-Key")
		assert.Contains(t, headers, "X-AWS-Session-Token")
	})
}

// TestGCPIdentityHeaders tests GCP identity header generation
func TestGCPIdentityHeaders(t *testing.T) {
	cloudProvider := determineCurrentCloudProvider(t)

	t.Run("GCP identity headers in GCP environment", func(t *testing.T) {
		if cloudProvider != "gcp" {
			t.Skip("Skipping GCP test in non-GCP environment")
		}

		t.Parallel()
		ctx := context.Background()

		headers, provider, err := getGCPIdentityHeaders(ctx, gcpDefaultAudience, "")
		require.NoError(t, err)
		assert.Equal(t, "gcp", provider)
		assert.Contains(t, headers, "Authorization")
		assert.True(t, strings.HasPrefix(headers["Authorization"], "Bearer "))
	})

	t.Run("GCP identity headers with mock metadata server", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Set up mock GCP metadata server
		_, gcpServer, _, cleanup := setupMockMetadataServers(t)
		defer cleanup()

		// Save and replace the real metadata URL
		origMetadataURL := gcpMetadataURL
		defer func() { gcpMetadataURL = origMetadataURL }()
		gcpMetadataURL = gcpServer.URL + "/"

		// Test getting identity token
		headers, provider, err := getGCPIdentityHeaders(ctx, "test-audience", "")
		require.NoError(t, err)
		assert.Equal(t, "gcp", provider)
		assert.Contains(t, headers, "Authorization")
		assert.True(t, strings.HasPrefix(headers["Authorization"], "Bearer "))
		assert.Contains(t, headers["Authorization"], "test-audience")
	})

	t.Run("GCP identity headers with service account impersonation", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Set up mock server for the token endpoint
		tokenServer := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// Verify this is a request to the IAM credentials API
			if !strings.Contains(r.URL.Path, "iamcredentials") {
				http.Error(w, "Invalid path", http.StatusBadRequest)
				return
			}

			// Verify the service account in the path
			serviceAccount := "test-service-account@project.iam.gserviceaccount.com"
			if !strings.Contains(r.URL.Path, serviceAccount) {
				http.Error(w, "Invalid service account", http.StatusBadRequest)
				return
			}

			// Read the request body to verify the audience
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read body", http.StatusBadRequest)
				return
			}

			// Check for audience in the request body
			var requestBody struct {
				Audience string `json:"audience"`
			}
			if err := json.Unmarshal(body, &requestBody); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			// Respond with a mock token
			response := struct {
				Token string `json:"token"`
			}{
				Token: fmt.Sprintf("mock-impersonated-token-for-%s", requestBody.Audience),
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		})
		defer tokenServer.Close()

		// Set up mock GCP metadata server for the self-token
		_, gcpServer, _, cleanup := setupMockMetadataServers(t)
		defer cleanup()

		// Save and restore original functions and URLs
		origMetadataURL := gcpMetadataURL
		origHTTPClient := httpClient
		defer func() {
			gcpMetadataURL = origMetadataURL
			httpClient = origHTTPClient
		}()

		// Set mock values
		gcpMetadataURL = gcpServer.URL + "/"

		// Create a custom HTTP client that redirects IAM credential requests to our mock server
		httpClient = &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				// If this is a request to the IAM credentials API, redirect to our mock server
				if strings.Contains(req.URL.Host, "iamcredentials.googleapis.com") {
					// Create a new URL with our test server
					newURL := tokenServer.URL + req.URL.Path
					if req.URL.RawQuery != "" {
						newURL += "?" + req.URL.RawQuery
					}

					// Create a new request with the same method, body, and headers
					newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
					if err != nil {
						return nil, err
					}
					newReq.Header = req.Header

					// Use the default client to make the request
					return http.DefaultClient.Do(newReq)
				}

				// Use the default client for other requests
				return http.DefaultClient.Do(req)
			}),
		}

		// Test with service account impersonation
		serviceAccount := "test-service-account@project.iam.gserviceaccount.com"
		headers, provider, err := getGCPIdentityHeaders(ctx, "custom-audience", serviceAccount)
		require.NoError(t, err)
		assert.Equal(t, "gcp", provider)
		assert.Contains(t, headers, "Authorization")
		assert.True(t, strings.HasPrefix(headers["Authorization"], "Bearer "))
		assert.Contains(t, headers["Authorization"], "mock-impersonated-token")
		assert.Contains(t, headers["Authorization"], "custom-audience")
	})
}

// Custom RoundTripper implementation for HTTP client mocking
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestAzureIdentityHeaders tests Azure identity header generation
func TestAzureIdentityHeaders(t *testing.T) {
	cloudProvider := determineCurrentCloudProvider(t)

	t.Run("Azure identity headers in Azure environment", func(t *testing.T) {
		if cloudProvider != "azure" {
			t.Skip("Skipping Azure test in non-Azure environment")
		}

		t.Parallel()
		ctx := context.Background()

		headers, provider, err := getAzureIdentityHeaders(ctx, "")
		require.NoError(t, err)
		assert.Equal(t, "azure", provider)
		assert.Contains(t, headers, "Authorization")
		assert.True(t, strings.HasPrefix(headers["Authorization"], "Bearer "))
	})

	t.Run("Azure identity headers with mock metadata server", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Set up mock Azure metadata server
		_, _, azureServer, cleanup := setupMockMetadataServers(t)
		defer cleanup()

		// Save and replace the real metadata URL
		origMetadataURL := azureMetadataURL
		defer func() { azureMetadataURL = origMetadataURL }()
		azureMetadataURL = azureServer.URL

		// Test getting access token
		headers, provider, err := getAzureIdentityHeaders(ctx, "")
		require.NoError(t, err)
		assert.Equal(t, "azure", provider)
		assert.Contains(t, headers, "Authorization")
		assert.True(t, strings.HasPrefix(headers["Authorization"], "Bearer "))
		assert.Contains(t, headers["Authorization"], "mock-azure-access-token")
	})

	t.Run("Azure identity headers with managed identity ID", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Set up mock Azure metadata server
		_, _, azureServer, cleanup := setupMockMetadataServers(t)
		defer cleanup()

		// Save and replace the real metadata URL
		origMetadataURL := azureMetadataURL
		defer func() { azureMetadataURL = origMetadataURL }()
		azureMetadataURL = azureServer.URL

		// Test with specific managed identity
		managedIdentityID := "12345678-1234-1234-1234-123456789012"
		headers, provider, err := getAzureIdentityHeaders(ctx, managedIdentityID)
		require.NoError(t, err)
		assert.Equal(t, "azure", provider)
		assert.Contains(t, headers, "Authorization")
		assert.True(t, strings.HasPrefix(headers["Authorization"], "Bearer "))
		assert.Contains(t, headers["Authorization"], "mock-azure-access-token")
	})
}

// TestGetIdentityHeaders tests the provider detection and identity header retrieval
func TestGetIdentityHeaders(t *testing.T) {
	t.Parallel()

	// Save original environment variables to restore later
	origAWSEnv := os.Getenv("AWS_EXECUTION_ENV")
	origGCPEnv := os.Getenv("GCE_METADATA_HOST")
	origAzureEnv := os.Getenv("AZURE_ENV")
	defer func() {
		os.Setenv("AWS_EXECUTION_ENV", origAWSEnv)
		os.Setenv("GCE_METADATA_HOST", origGCPEnv)
		os.Setenv("AZURE_ENV", origAzureEnv)
	}()

	// Save original provider-specific functions
	origAWSHeaders := getAWSIdentityHeaders
	origGCPHeaders := getGCPIdentityHeaders
	origAzureHeaders := getAzureIdentityHeaders
	defer func() {
		getAWSIdentityHeaders = origAWSHeaders
		getGCPIdentityHeaders = origGCPHeaders
		getAzureIdentityHeaders = origAzureHeaders
	}()

	t.Run("AWS provider detection", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Set AWS environment variable and clear others
		os.Setenv("AWS_EXECUTION_ENV", "AWS_Lambda")
		os.Setenv("GCE_METADATA_HOST", "")
		os.Setenv("AZURE_ENV", "")

		// Mock AWS identity headers function
		getAWSIdentityHeaders = func(ctx context.Context, roleARN string) (map[string]string, string, error) {
			return map[string]string{
				"X-AWS-Access-Key-ID":     "test-access-key",
				"X-AWS-Secret-Access-Key": "test-secret-key",
				"X-AWS-Session-Token":     "test-session-token",
			}, "aws", nil
		}

		// Test getIdentityHeaders
		headers, provider, err := getIdentityHeaders(ctx, "test-audience", "")
		require.NoError(t, err)
		assert.Equal(t, "aws", provider)
		assert.Equal(t, "test-access-key", headers["X-AWS-Access-Key-ID"])
	})

	t.Run("GCP provider detection", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Set GCP environment variable and clear others
		os.Setenv("AWS_EXECUTION_ENV", "")
		os.Setenv("GCE_METADATA_HOST", "metadata.google.internal")
		os.Setenv("AZURE_ENV", "")

		// Mock GCP identity headers function
		getGCPIdentityHeaders = func(ctx context.Context, audience string, serviceAccountEmail string) (map[string]string, string, error) {
			return map[string]string{
				"Authorization": "Bearer test-gcp-token",
			}, "gcp", nil
		}

		// Test getIdentityHeaders
		headers, provider, err := getIdentityHeaders(ctx, "test-audience", "")
		require.NoError(t, err)
		assert.Equal(t, "gcp", provider)
		assert.Equal(t, "Bearer test-gcp-token", headers["Authorization"])
	})

	t.Run("Azure provider detection", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Set Azure environment variable and clear others
		os.Setenv("AWS_EXECUTION_ENV", "")
		os.Setenv("GCE_METADATA_HOST", "")
		os.Setenv("AZURE_ENV", "AzurePublicCloud")

		// Mock Azure identity headers function
		getAzureIdentityHeaders = func(ctx context.Context, managedIdentityID string) (map[string]string, string, error) {
			return map[string]string{
				"Authorization": "Bearer test-azure-token",
			}, "azure", nil
		}

		// Test getIdentityHeaders
		headers, provider, err := getIdentityHeaders(ctx, "test-audience", "")
		require.NoError(t, err)
		assert.Equal(t, "azure", provider)
		assert.Equal(t, "Bearer test-azure-token", headers["Authorization"])
	})

	t.Run("No provider detected", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Clear all environment variables
		os.Setenv("AWS_EXECUTION_ENV", "")
		os.Setenv("GCE_METADATA_HOST", "")
		os.Setenv("AZURE_ENV", "")

		// Test getIdentityHeaders
		_, _, err := getIdentityHeaders(ctx, "test-audience", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cloud provider not detected")
	})

	t.Run("Provider error handling", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Set AWS environment variable
		os.Setenv("AWS_EXECUTION_ENV", "AWS_Lambda")
		os.Setenv("GCE_METADATA_HOST", "")
		os.Setenv("AZURE_ENV", "")

		// Mock AWS identity headers function to return error
		getAWSIdentityHeaders = func(ctx context.Context, roleARN string) (map[string]string, string, error) {
			return nil, "", errors.New("AWS credentials error")
		}

		// Test getIdentityHeaders
		_, _, err := getIdentityHeaders(ctx, "test-audience", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get identity headers")
		assert.Contains(t, err.Error(), "AWS credentials error")
	})
}

// TestGetJWT tests the core JWT retrieval function
func TestGetJWT(t *testing.T) {
	t.Parallel()

	// Save original functions to restore later
	origGetIdentityHeaders := getIdentityHeaders
	defer func() { getIdentityHeaders = origGetIdentityHeaders }()

	// Create mock auth server
	server := createMockAuthServer(t)
	defer server.Close()

	t.Run("Basic JWT retrieval", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Mock identity headers for AWS
		getIdentityHeaders = func(ctx context.Context, gcpAudience string, assumeRoleIdentifier string) (map[string]string, string, error) {
			return map[string]string{
				"X-AWS-Access-Key-ID":     "test-access-key",
				"X-AWS-Secret-Access-Key": "test-secret-key",
				"X-AWS-Session-Token":     "test-session-token",
			}, "aws", nil
		}

		// Create options for database JWT
		options := jwtOptions{
			JWTType:           DatabaseAccessJWT,
			WorkspaceGroupID:  "test-workspace",
			ExternalServerURL: server.URL,
		}

		// Test getJWT
		jwt, err := getJWT(ctx, options)
		require.NoError(t, err)
		assert.Contains(t, jwt, "mock.aws.jwt")
	})

	t.Run("API JWT retrieval", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Mock identity headers for GCP
		getIdentityHeaders = func(ctx context.Context, gcpAudience string, assumeRoleIdentifier string) (map[string]string, string, error) {
			return map[string]string{
				"Authorization": "Bearer gcp-token-0123456789abcdefghijklmnopqrstuvwxyz",
			}, "gcp", nil
		}

		// Create options for API JWT
		options := jwtOptions{
			JWTType:           APIGatewayAccessJWT,
			ExternalServerURL: server.URL,
		}

		// Test getJWT
		jwt, err := getJWT(ctx, options)
		require.NoError(t, err)
		assert.Contains(t, jwt, "mock.gcp.jwt")
	})

	t.Run("Identity headers error", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Mock identity headers to return error
		getIdentityHeaders = func(ctx context.Context, gcpAudience string, assumeRoleIdentifier string) (map[string]string, string, error) {
			return nil, "", errors.New("identity error")
		}

		// Create options
		options := jwtOptions{
			JWTType:           DatabaseAccessJWT,
			WorkspaceGroupID:  "test-workspace",
			ExternalServerURL: server.URL,
		}

		// Test getJWT
		_, err := getJWT(ctx, options)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get identity headers")
	})

	t.Run("HTTP error handling", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Create a server that returns an error
		errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}))
		defer errorServer.Close()

		// Mock identity headers for AWS
		getIdentityHeaders = func(ctx context.Context, gcpAudience string, assumeRoleIdentifier string) (map[string]string, string, error) {
			return map[string]string{
				"X-AWS-Access-Key-ID":     "test-access-key",
				"X-AWS-Secret-Access-Key": "test-secret-key",
				"X-AWS-Session-Token":     "test-session-token",
			}, "aws", nil
		}

		// Create options
		options := jwtOptions{
			JWTType:           DatabaseAccessJWT,
			WorkspaceGroupID:  "test-workspace",
			ExternalServerURL: errorServer.URL,
		}

		// Test getJWT
		_, err := getJWT(ctx, options)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "non-OK status")
		assert.Contains(t, err.Error(), "401")
	})

	t.Run("Invalid response format", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Create a server that returns invalid JSON
		invalidServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not json"))
		}))
		defer invalidServer.Close()

		// Mock identity headers for AWS
		getIdentityHeaders = func(ctx context.Context, gcpAudience string, assumeRoleIdentifier string) (map[string]string, string, error) {
			return map[string]string{
				"X-AWS-Access-Key-ID":     "test-access-key",
				"X-AWS-Secret-Access-Key": "test-secret-key",
				"X-AWS-Session-Token":     "test-session-token",
			}, "aws", nil
		}

		// Create options
		options := jwtOptions{
			JWTType:           DatabaseAccessJWT,
			WorkspaceGroupID:  "test-workspace",
			ExternalServerURL: invalidServer.URL,
		}

		// Test getJWT
		_, err := getJWT(ctx, options)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot parse response")
	})

	t.Run("Empty JWT response", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Create a server that returns empty JWT
		emptyJWTServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jwt":""}`))
		}))
		defer emptyJWTServer.Close()

		// Mock identity headers for AWS
		getIdentityHeaders = func(ctx context.Context, gcpAudience string, assumeRoleIdentifier string) (map[string]string, string, error) {
			return map[string]string{
				"X-AWS-Access-Key-ID":     "test-access-key",
				"X-AWS-Secret-Access-Key": "test-secret-key",
				"X-AWS-Session-Token":     "test-session-token",
			}, "aws", nil
		}

		// Create options
		options := jwtOptions{
			JWTType:           DatabaseAccessJWT,
			WorkspaceGroupID:  "test-workspace",
			ExternalServerURL: emptyJWTServer.URL,
		}

		// Test getJWT
		_, err := getJWT(ctx, options)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "received empty JWT from server")
	})
}

// TestGetDatabaseJWT tests the database JWT retrieval
func TestGetDatabaseJWT(t *testing.T) {
	t.Parallel()

	// Save original getJWT function to restore later
	origGetJWT := getJWT
	defer func() { getJWT = origGetJWT }()

	t.Run("Database JWT request parameters", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Mock getJWT to verify options
		getJWT = func(ctx context.Context, options jwtOptions) (string, error) {
			// Verify options
			assert.Equal(t, DatabaseAccessJWT, options.JWTType)
			assert.Equal(t, "test-workspace", options.WorkspaceGroupID)
			assert.Equal(t, "https://custom.auth.server.com", options.ExternalServerURL)
			assert.Equal(t, "custom-audience", options.GCPAudience)
			assert.Equal(t, "test-role", options.AssumeRoleIdentifier)

			return "mock.jwt.token", nil
		}

		// Get database JWT with options
		jwt, err := GetDatabaseJWT(ctx, "test-workspace",
			WithExternalServerURL("https://custom.auth.server.com"),
			WithGCPAudience("custom-audience"),
			WithAssumeRole("test-role"))

		require.NoError(t, err)
		assert.Equal(t, "mock.jwt.token", jwt)
	})

	t.Run("Default values", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Mock getJWT to verify default options
		getJWT = func(ctx context.Context, options jwtOptions) (string, error) {
			// Verify default options
			assert.Equal(t, DatabaseAccessJWT, options.JWTType)
			assert.Equal(t, "test-workspace", options.WorkspaceGroupID)
			assert.Equal(t, defaultServer, options.ExternalServerURL)
			assert.Equal(t, "", options.GCPAudience) // Default is empty, set in getJWT
			assert.Equal(t, "", options.AssumeRoleIdentifier)

			return "mock.jwt.token", nil
		}

		// Get database JWT with default options
		jwt, err := GetDatabaseJWT(ctx, "test-workspace")

		require.NoError(t, err)
		assert.Equal(t, "mock.jwt.token", jwt)
	})

	t.Run("Integration with getJWT", func(t *testing.T) {
		cloudProvider := determineCurrentCloudProvider(t)
		if cloudProvider == "none" {
			t.Skip("Skipping integration test in non-cloud environment")
		}

		// Create mock server
		server := createMockAuthServer(t)
		defer server.Close()

		// Restore original getJWT
		getJWT = origGetJWT

		// Test in actual cloud environment
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		jwt, err := GetDatabaseJWT(ctx, "test-workspace-group",
			WithExternalServerURL(server.URL))

		// The test may fail due to actual cloud provider interactions
		if err != nil {
			t.Log("JWT retrieval failed (expected in restricted environment): %v", err)
		} else {
			assert.NotEmpty(t, jwt)
			t.Logf"Successfully retrieved JWT: %s", jwt)
		}
	})
}

// TestGetAPIJWT tests the API JWT retrieval
func TestGetAPIJWT(t *testing.T) {
	t.Parallel()

	// Save original getJWT function to restore later
	origGetJWT := getJWT
	defer func() { getJWT = origGetJWT }()

	t.Run("API JWT request parameters", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Mock getJWT to verify options
		getJWT = func(ctx context.Context, options jwtOptions) (string, error) {
			// Verify options
			assert.Equal(t, APIGatewayAccessJWT, options.JWTType)
			assert.Equal(t, "", options.WorkspaceGroupID) // Not used for API JWT
			assert.Equal(t, "https://custom.auth.server.com", options.ExternalServerURL)
			assert.Equal(t, "custom-audience", options.GCPAudience)
			assert.Equal(t, "test-role", options.AssumeRoleIdentifier)

			return "mock.api.jwt.token", nil
		}

		// Get API JWT with options
		jwt, err := GetAPIJWT(ctx,
			WithExternalServerURL("https://custom.auth.server.com"),
			WithGCPAudience("custom-audience"),
			WithAssumeRole("test-role"))

		require.NoError(t, err)
		assert.Equal(t, "mock.api.jwt.token", jwt)
	})

	t.Run("Default values", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Mock getJWT to verify default options
		getJWT = func(ctx context.Context, options jwtOptions) (string, error) {
			// Verify default options
			assert.Equal(t, APIGatewayAccessJWT, options.JWTType)
			assert.Equal(t, "", options.WorkspaceGroupID)
			assert.Equal(t, defaultServer, options.ExternalServerURL)
			assert.Equal(t, "", options.GCPAudience) // Default is empty, set in getJWT
			assert.Equal(t, "", options.AssumeRoleIdentifier)

			return "mock.api.jwt.token", nil
		}

		// Get API JWT with default options
		jwt, err := GetAPIJWT(ctx)

		require.NoError(t, err)
		assert.Equal(t, "mock.api.jwt.token", jwt)
	})

	t.Run("Integration with getJWT", func(t *testing.T) {
		cloudProvider := determineCurrentCloudProvider(t)
		if cloudProvider == "none" {
			t.Skip("Skipping integration test in non-cloud environment")
		}

		// Create mock server
		server := createMockAuthServer(t)
		defer server.Close()

		// Restore original getJWT
		getJWT = origGetJWT

		// Test in actual cloud environment
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		jwt, err := GetAPIJWT(ctx, WithExternalServerURL(server.URL))

		// The test may fail due to actual cloud provider interactions
		if err != nil {
			t.Logf("JWT retrieval failed (expected in restricted environment): %v", err)
		} else {
			assert.NotEmpty(t, jwt)
			t.Logf("Successfully retrieved JWT: %s", jwt)
		}
	})
}

// TestMetadataRetrieval tests the metadata retrieval functions
func TestMetadataRetrieval(t *testing.T) {
	cloudProvider := determineCurrentCloudProvider(t)

	// Set up mock metadata servers
	awsServer, gcpServer, azureServer, cleanup := setupMockMetadataServers(t)
	defer cleanup()

	// Save original URLs
	origAWSMetadataURL := awsMetadataURL
	origGCPMetadataURL := gcpMetadataURL
	origAzureMetadataURL := azureMetadataURL
	defer func() {
		awsMetadataURL = origAWSMetadataURL
		gcpMetadataURL = origGCPMetadataURL
		azureMetadataURL = origAzureMetadataURL
	}()

	// Set mock URLs
	awsMetadataURL = awsServer.URL + "/"
	gcpMetadataURL = gcpServer.URL + "/"
	azureMetadataURL = azureServer.URL

	t.Run("Mock AWS metadata retrieval", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Test getting instance ID
		data, err := getAWSMetadata(ctx, "instance-id")
		require.NoError(t, err)
		assert.Equal(t, "i-1234567890abcdef0", strings.TrimSpace(data))

		// Test getting IAM info
		data, err = getAWSMetadata(ctx, "iam/info")
		require.NoError(t, err)
		assert.Contains(t, data, "InstanceProfileArn")
	})

	t.Run("Mock GCP ID token retrieval", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Test getting ID token
		token, err := getGCPIDToken(ctx, "test-audience")
		require.NoError(t, err)
		assert.Equal(t, "gcp-mock-identity-token-for-test-audience", token)
	})

	t.Run("Real metadata retrieval", func(t *testing.T) {
		if cloudProvider == "none" {
			t.Skip("Skipping real metadata test in non-cloud environment")
		}

		// Restore original URLs for real tests
		awsMetadataURL = origAWSMetadataURL
		gcpMetadataURL = origGCPMetadataURL
		azureMetadataURL = origAzureMetadataURL

		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		switch cloudProvider {
		case "aws":
			// Test AWS metadata retrieval
			data, err := getAWSMetadata(ctx, "instance-id")
			if err != nil {
				t.Logf("AWS metadata retrieval failed (might not have right permissions): %v", err)
			} else {
				assert.NotEmpty(t, data)
				t.Logf("Successfully retrieved AWS instance ID: %s", data)
			}

		case "gcp":
			// Test GCP ID token retrieval
			token, err := getGCPIDToken(ctx, gcpDefaultAudience)
			if err != nil {
				t.Logf("GCP ID token retrieval failed (might not have right permissions): %v", err)
			} else {
				assert.NotEmpty(t, token)
				t.Log("Successfully retrieved GCP ID token")
			}

		case "azure":
			// Test Azure metadata retrieval with real API
			url := fmt.Sprintf("%s?api-version=%s&resource=%s",
				azureMetadataURL, azureAPIVersion, azureResourceServer)

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			require.NoError(t, err)
			req.Header.Set("Metadata", "true")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Logf("Azure metadata request failed: %v", err)
			} else {
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Logf("Failed to read Azure metadata response: %v", err)
				} else if resp.StatusCode != http.StatusOK {
					t.Logf("Azure metadata returned non-OK status: %d, %s", resp.StatusCode, string(body))
				} else {
					assert.NotEmpty(t, body)
					t.Logf("Successfully retrieved Azure metadata")
				}
			}
		}
	})
}

// TestVerifierIntegration tests integration with the verifier library
func TestVerifierIntegration(t *testing.T) {
	// Skip if verifier package is not available
	if _, err := os.Stat("../verifier"); os.IsNotExist(err) {
		t.Skip("Skipping verifier integration test - verifier package not available")
	}

	// Create mock server for the verification endpoint
	verifierServer := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Extract auth headers
		var provider string
		if r.Header.Get("X-AWS-Access-Key-ID") != "" {
			provider = "aws"
		} else if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer gcp") {
			provider = "gcp"
		} else if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer azure") {
			provider = "azure"
		} else {
			http.Error(w, "Invalid auth headers", http.StatusUnauthorized)
			return
		}

		// Create cloud identity based on the detected provider
		var identifier, accountID, resourceType string
		switch provider {
		case "aws":
			identifier = "arn:aws:iam::123456789012:role/test-role"
			accountID = "123456789012"
			resourceType = "ec2"
		case "gcp":
			identifier = "123456789012/vm-1234/service-account@project.iam.gserviceaccount.com"
			accountID = "my-project-123"
			resourceType = "gce"
		case "azure":
			identifier = "12345678-1234-1234-1234-123456789012"
			accountID = "my-subscription"
			resourceType = "vm"
		}

		// Return a JSON response with the cloud identity
		identity := verifier.CloudIdentity{
			Provider:         provider,
			Identifier:       identifier,
			AccountID:        accountID,
			Region:           "us-west-2",
			ResourceType:     resourceType,
			AdditionalClaims: map[string]string{"test": "value"},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(identity)
	})
	defer verifierServer.Close()

	// Create a test config with our test server as the audience
	config := verifier.VerifierConfig{
		AllowedAudiences: []string{verifierServer.URL},
		LogLevel:         verifier.LogLevelDebug,
	}

	// Create a verifier instance
	v, err := verifier.NewVerifier(context.Background(), config)
	require.NoError(t, err)

	t.Run("Verify AWS request", func(t *testing.T) {
		t.Parallel()

		// Create a mock AWS request
		req, err := http.NewRequest(http.MethodGet, verifierServer.URL, nil)
		require.NoError(t, err)

		// Add AWS headers
		req.Header.Set("X-AWS-Access-Key-ID", "test-access-key")
		req.Header.Set("X-AWS-Secret-Access-Key", "test-secret-key")
		req.Header.Set("X-AWS-Session-Token", "test-session-token")

		// Verify the request
		identity, err := v.VerifyRequest(context.Background(), req)
		require.NoError(t, err)

		// Verify the identity
		assert.Equal(t, "aws", identity.Provider)
		assert.Equal(t, "arn:aws:iam::123456789012:role/test-role", identity.Identifier)
		assert.Equal(t, "123456789012", identity.AccountID)
	})

	t.Run("Verify GCP request", func(t *testing.T) {
		t.Parallel()

		// Create a mock GCP request
		req, err := http.NewRequest(http.MethodGet, verifierServer.URL, nil)
		require.NoError(t, err)

		// Add GCP token
		req.Header.Set("Authorization", "Bearer gcp-test-token")

		// Verify the request
		identity, err := v.VerifyRequest(context.Background(), req)
		require.NoError(t, err)

		// Verify the identity
		assert.Equal(t, "gcp", identity.Provider)
		assert.Contains(t, identity.Identifier, "service-account")
		assert.Equal(t, "my-project-123", identity.AccountID)
	})
}

// TestMockCloudVerifier tests the mock implementation of the CloudVerifier interface
func TestMockCloudVerifier(t *testing.T) {
	t.Parallel()

	t.Run("VerifyRequest success", func(t *testing.T) {
		t.Parallel()

		// Create mock verifier
		mockVerifier := new(MockCloudVerifier)

		// Set up expectations
		mockIdentity := &verifier.CloudIdentity{
			Provider:     "aws",
			Identifier:   "arn:aws:iam::123456789012:role/test-role",
			AccountID:    "123456789012",
			Region:       "us-west-2",
			ResourceType: "ec2",
		}

		mockVerifier.On("VerifyRequest", mock.Anything, mock.Anything).Return(mockIdentity, nil)

		// Create test request
		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		// Call the method
		identity, err := mockVerifier.VerifyRequest(context.Background(), req)

		// Assertions
		require.NoError(t, err)
		assert.Equal(t, mockIdentity, identity)
		mockVerifier.AssertExpectations(t)
	})

	t.Run("VerifyRequest error", func(t *testing.T) {
		t.Parallel()

		// Create mock verifier
		mockVerifier := new(MockCloudVerifier)

		// Set up expectations for error
		expectedErr := errors.New("authentication failed")
		mockVerifier.On("VerifyRequest", mock.Anything, mock.Anything).Return(nil, expectedErr)

		// Create test request
		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		// Call the method
		identity, err := mockVerifier.VerifyRequest(context.Background(), req)

		// Assertions
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.Nil(t, identity)
		mockVerifier.AssertExpectations(t)
	})
}

// TestAssumeRoleIntegration tests the assume role functionality in each cloud provider
func TestAssumeRoleIntegration(t *testing.T) {
	cloudProvider := determineCurrentCloudProvider(t)

	t.Run("AWS assume role", func(t *testing.T) {
		if cloudProvider != "aws" {
			t.Skip("Skipping AWS assume role test in non-AWS environment")
		}

		t.Parallel()
		ctx := context.Background()

		// Create mock server
		server := createMockAuthServer(t)
		defer server.Close()

		// Test assume role with database JWT
		roleARN := "arn:aws:iam::123456789012:role/test-role"
		jwt, err := GetDatabaseJWT(ctx, "test-workspace",
			WithExternalServerURL(server.URL),
			WithAssumeRole(roleARN))

		if err != nil {
			// In real AWS, might fail due to permissions
			t.Logf("JWT retrieval with assume role failed (expected in restricted environment): %v", err)
		} else {
			assert.Contains(t, jwt, "mock.aws.jwt")
			t.Logf("Successfully retrieved JWT with assumed role: %s", jwt)
		}
	})

	t.Run("GCP service account impersonation", func(t *testing.T) {
		if cloudProvider != "gcp" && cloudProvider != "none" {
			t.Skip("Skipping GCP service account impersonation test in non-GCP environment")
		}

		t.Parallel()
		ctx := context.Background()

		// Create mock server
		server := createMockAuthServer(t)
		defer server.Close()

		if cloudProvider == "none" {
			// Set up mock for service account impersonation
			// Save and replace functions
			origGetIdentityHeaders := getIdentityHeaders
			defer func() { getIdentityHeaders = origGetIdentityHeaders }()

			getIdentityHeaders = func(ctx context.Context, gcpAudience string, assumeRoleIdentifier string) (map[string]string, string, error) {
				// Check if impersonation is requested
				if assumeRoleIdentifier != "" {
					// Mock impersonated token
					return map[string]string{
						"Authorization": "Bearer impersonated-gcp-token",
					}, "gcp", nil
				}

				// Mock standard token
				return map[string]string{
					"Authorization": "Bearer gcp-token",
				}, "gcp", nil
			}
		}

		// Test impersonation with API JWT
		serviceAccount := "service-account@project.iam.gserviceaccount.com"
		jwt, err := GetAPIJWT(ctx,
			WithExternalServerURL(server.URL),
			WithGCPAudience("custom-audience"),
			WithAssumeRole(serviceAccount))

		if err != nil {
			// In real GCP, might fail due to permissions
			t.Logf("JWT retrieval with service account impersonation failed (expected in restricted environment): %v", err)
		} else {
			assert.Contains(t, jwt, "mock.gcp.jwt")
			t.Logf("Successfully retrieved JWT with impersonated service account: %s", jwt)
		}
	})

	t.Run("Azure managed identity selection", func(t *testing.T) {
		if cloudProvider != "azure" && cloudProvider != "none" {
			t.Skip("Skipping Azure managed identity test in non-Azure environment")
		}

		t.Parallel()
		ctx := context.Background()

		// Create mock server
		server := createMockAuthServer(t)
		defer server.Close()

		if cloudProvider == "none" {
			// Set up mock for managed identity selection
			// Save and replace functions
			origGetIdentityHeaders := getIdentityHeaders
			defer func() { getIdentityHeaders = origGetIdentityHeaders }()

			getIdentityHeaders = func(ctx context.Context, gcpAudience string, assumeRoleIdentifier string) (map[string]string, string, error) {
				// Check if specific identity is requested
				if assumeRoleIdentifier != "" {
					// Mock specific identity token
					return map[string]string{
						"Authorization": "Bearer specific-azure-identity-token",
					}, "azure", nil
				}

				// Mock default identity token
				return map[string]string{
					"Authorization": "Bearer default-azure-token",
				}, "azure", nil
			}
		}

		// Test with specific managed identity
		managedIdentityID := "12345678-1234-1234-1234-123456789012"
		jwt, err := GetAPIJWT(ctx,
			WithExternalServerURL(server.URL),
			WithAssumeRole(managedIdentityID))

		if err != nil {
			// In real Azure, might fail due to permissions
			t.Logf("JWT retrieval with managed identity selection failed (expected in restricted environment): %v", err)
		} else {
			assert.Contains(t, jwt, "mock.azure.jwt")
			t.Logf("Successfully retrieved JWT with specific managed identity: %s", jwt)
		}
	})
}

// TestEndToEndIntegration performs an end-to-end test with Verifier
func TestEndToEndIntegration(t *testing.T) {
	cloudProvider := determineCurrentCloudProvider(t)
	if cloudProvider == "none" {
		t.Skip("Skipping end-to-end test in non-cloud environment")
	}

	// Set up mock auth server to simulate the database/API gateway
	authServer := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify request using the Verifier
		// In a real scenario, this would create a real verifier and validate real cloud credentials

		// For testing purposes, we'll check headers directly
		var provider string
		if r.Header.Get("X-AWS-Access-Key-ID") != "" {
			provider = "aws"
		} else if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			// Simplified check for GCP or Azure
			if len(r.Header.Get("Authorization")) > 50 {
				provider = "gcp"
			} else {
				provider = "azure"
			}
		} else {
			http.Error(w, "Unauthorized: No valid cloud credentials", http.StatusUnauthorized)
			return
		}

		// Return a mock JWT
		response := struct {
			JWT string `json:"jwt"`
		}{
			JWT: fmt.Sprintf("end-to-end.%s.test.jwt.%s", provider, time.Now().Format(time.RFC3339)),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	defer authServer.Close()

	// Set up test context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("End-to-end database JWT flow", func(t *testing.T) {
		// Get a database JWT
		jwt, err := GetDatabaseJWT(ctx, "test-workspace-group",
			WithExternalServerURL(authServer.URL))

		if err != nil {
			t.Logf("End-to-end database JWT retrieval failed (expected in restricted environment): %v", err)
		} else {
			assert.Contains(t, jwt, "end-to-end")
			assert.Contains(t, jwt, cloudProvider)
			t.Logf("Successfully retrieved end-to-end database JWT: %s", jwt)
		}
	})

	t.Run("End-to-end API JWT flow", func(t *testing.T) {
		// Get an API JWT
		jwt, err := GetAPIJWT(ctx,
			WithExternalServerURL(authServer.URL))

		if err != nil {
			t.Logf("End-to-end API JWT retrieval failed (expected in restricted environment): %v", err)
		} else {
			assert.Contains(t, jwt, "end-to-end")
			assert.Contains(t, jwt, cloudProvider)
			t.Logf("Successfully retrieved end-to-end API JWT: %s", jwt)
		}
	})
}

// Mock HTTP client
var httpClient = http.DefaultClient

*/
