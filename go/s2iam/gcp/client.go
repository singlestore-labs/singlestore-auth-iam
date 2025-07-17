package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/memsql/errors"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
	"google.golang.org/api/idtoken"
)

const (
	// GCP metadata service URL
	gcpMetadataURL = "http://metadata.google.internal/computeMetadata/v1/"

	// Default audience for identity tokens
	defaultAudience = "https://auth.singlestore.com"
)

// GCPClient implements the CloudProviderClient interface for GCP
type GCPClient struct {
	serviceAccountEmail string
	identity            *models.CloudIdentity
	detected            bool
	logger              models.Logger // Added logger field
	mu                  sync.Mutex    // Added for concurrency safety
}

func (c *GCPClient) copy() *GCPClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &GCPClient{
		serviceAccountEmail: c.serviceAccountEmail,
		identity:            c.identity,
		detected:            c.detected,
		logger:              c.logger,
	}
}

// gcpClient is a singleton instance for GCPClient
var gcpClient = &GCPClient{}

// NewClient returns the GCP client singleton
func NewClient(logger models.Logger) models.CloudProviderClient {
	gcpClient.mu.Lock()
	defer gcpClient.mu.Unlock()

	gcpClient.logger = logger
	return gcpClient
}

// Detect tests if we are executing within GCP
func (c *GCPClient) Detect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if detection was already performed successfully
	if c.detected {
		return nil
	}

	// Check GCP environment variable (fast check first)
	if os.Getenv("GCE_METADATA_HOST") != "" {
		c.detected = true
		if c.logger != nil {
			c.logger.Logf("GCP Detection - Found GCE_METADATA_HOST environment variable")
		}

		// Verify we can actually get identity information
		testCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		// Try to access identity-related metadata
		req, err := http.NewRequestWithContext(testCtx, http.MethodGet,
			gcpMetadataURL+"instance/service-accounts/default/", nil)
		if err != nil {
			c.detected = false
			return errors.WithStack(models.ErrProviderDetectedNoIdentity)
		}

		req.Header.Set("Metadata-Flavor", "Google")
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				_ = resp.Body.Close()
			}
			if c.logger != nil {
				c.logger.Logf("GCP Detection - Metadata service available but no identity access")
			}
			return errors.WithStack(models.ErrProviderDetectedNoIdentity)
		}
		_ = resp.Body.Close()

		return nil
	}

	// Try to access the GCP metadata service
	if c.logger != nil {
		c.logger.Logf("GCP Detection - Trying metadata service")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		gcpMetadataURL+"instance/id", nil)
	if err != nil {
		return errors.Errorf("not running on GCP: metadata service unavailable (no GCE_METADATA_HOST env var and cannot reach metadata.google.internal): %w", err)
	}

	req.Header.Set("Metadata-Flavor", "Google")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if c.logger != nil {
			c.logger.Logf("GCP Detection - Metadata service unavailable: %v", err)
		}
		return errors.Errorf("not running on GCP: metadata service unavailable (no GCE_METADATA_HOST env var and cannot reach metadata.google.internal): %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		if c.logger != nil {
			c.logger.Logf("GCP Detection - Metadata service returned status %d", resp.StatusCode)
		}
		return errors.Errorf("not running on GCP: metadata service returned status %d", resp.StatusCode)
	}

	_ = resp.Body.Close()
	c.detected = true
	if c.logger != nil {
		c.logger.Logf("GCP Detection - Successfully detected GCP environment")
	}
	return nil
}

// GetType returns the cloud provider type
func (c *GCPClient) GetType() models.CloudProviderType {
	return models.ProviderGCP
}

// GetIdentityHeaders returns the headers needed to authenticate with the SingleStore auth service
func (c *GCPClient) GetIdentityHeaders(ctx context.Context, additionalParams map[string]string) (map[string]string, *models.CloudIdentity, error) {
	c.mu.Lock()
	detected := c.detected
	serviceAccountEmail := c.serviceAccountEmail
	c.mu.Unlock()

	if !detected {
		return nil, nil, errors.WithStack(models.ErrProviderNotDetected)
	}

	// Determine the audience to use
	audience := defaultAudience
	if audienceParam, ok := additionalParams["audience"]; ok && audienceParam != "" {
		audience = audienceParam
	}

	// If serviceAccountEmail is provided, get token through impersonation
	if serviceAccountEmail != "" {
		if c.logger != nil {
			c.logger.Logf("GCP Impersonation - Starting impersonation for service account: %s", serviceAccountEmail)
		}

		// IMPORTANT: To authenticate with the IAM Service Account Credentials API,
		// we need an OAuth 2.0 access token, NOT an identity token.
		// Identity tokens are meant for authenticating the identity of the caller,
		// while access tokens are used for API authorization.
		// The IAM API expects an access token with the cloud-platform scope.
		selfToken, err := c.getAccessToken(ctx)
		if err != nil {
			if c.logger != nil {
				c.logger.Logf("GCP Impersonation - Failed to get access token: %v", err)
			}
			return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
		}

		if c.logger != nil {
			// Log token length and first few characters for debugging (not the whole token for security)
			tokenPreview := "empty"
			if len(selfToken) > 10 {
				tokenPreview = fmt.Sprintf("%d chars, starts with: %s...", len(selfToken), selfToken[:10])
			}
			c.logger.Logf("GCP Impersonation - Got access token for IAM API: %s", tokenPreview)
		}

		// Use IAM API to impersonate the service account
		impersonationURL := fmt.Sprintf(
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken",
			serviceAccountEmail,
		)

		if c.logger != nil {
			c.logger.Logf("GCP Impersonation - Calling impersonation URL: %s", impersonationURL)
			c.logger.Logf("GCP Impersonation - Request audience: %s", audience)
		}

		requestBody := fmt.Sprintf(`{"audience":"%s"}`, audience)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, impersonationURL, strings.NewReader(requestBody))
		if err != nil {
			return nil, nil, errors.Errorf("failed to create impersonation request: %w", err)
		}

		// Use our self token to authenticate the impersonation request
		req.Header.Set("Authorization", "Bearer "+selfToken)
		req.Header.Set("Content-Type", "application/json")

		if c.logger != nil {
			c.logger.Logf("GCP Impersonation - Sending request with Authorization header set")
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			if c.logger != nil {
				c.logger.Logf("GCP Impersonation - HTTP request failed: %v", err)
			}
			return nil, nil, errors.Errorf("failed to impersonate service account: %w", err)
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			if c.logger != nil {
				c.logger.Logf("GCP Impersonation - Request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
				// Also log the request details for debugging
				c.logger.Logf("GCP Impersonation - Failed request details - URL: %s, Method: %s, Content-Type: %s",
					impersonationURL, req.Method, req.Header.Get("Content-Type"))

				// Add helpful error messages for common issues
				if resp.StatusCode == 401 {
					c.logger.Logf("GCP Impersonation - 401 Unauthorized suggests the access token is invalid or lacks proper scopes")
				} else if resp.StatusCode == 403 {
					c.logger.Logf("GCP Impersonation - 403 Forbidden suggests either:")
					c.logger.Logf("  1. The service account lacks 'Service Account Token Creator' role on the target service account")
					c.logger.Logf("  2. The GCP instance was not created with the necessary scopes (cloud-platform or iam)")
					c.logger.Logf("  3. The instance needs to be recreated with: --scopes=https://www.googleapis.com/auth/cloud-platform")
				}
			}
			return nil, nil, errors.Errorf("impersonation failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		}

		if c.logger != nil {
			c.logger.Logf("GCP Impersonation - Successfully received response")
		}

		var tokenResponse struct {
			Token string `json:"token"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
			return nil, nil, errors.Errorf("failed to parse impersonation response: %w", err)
		}

		if tokenResponse.Token == "" {
			return nil, nil, errors.Errorf("received empty token from impersonation service")
		}

		headers := map[string]string{
			"Authorization": "Bearer " + tokenResponse.Token,
		}

		// Create identity object
		identity, err := c.getIdentityFromToken(ctx, tokenResponse.Token)
		if err != nil {
			return nil, nil, errors.Errorf("got headers but failed to extract identity: %w", err) // Return headers even if identity extraction fails
		}

		return headers, identity, nil
	}

	// Original implementation when no service account impersonation is needed
	idToken, err := c.getIDToken(ctx, audience)
	if err != nil {
		return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + idToken,
	}

	// Create identity object
	identity, err := c.getIdentityFromToken(ctx, idToken)
	if err != nil {
		return nil, nil, errors.Errorf("got headers but failed to extract identity: %w", err) // Return headers even if identity extraction fails
	}

	return headers, identity, nil
}

// getIDToken retrieves a GCP identity token for the given audience
func (c *GCPClient) getIDToken(ctx context.Context, audience string) (string, error) {
	tokenURL := fmt.Sprintf("%sinstance/service-accounts/default/identity?audience=%s", gcpMetadataURL, audience)

	if c.logger != nil {
		c.logger.Logf("GCP Token - Requesting token from metadata service: %s", tokenURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", errors.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google") // Correct header for GCP metadata service

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if c.logger != nil {
			c.logger.Logf("GCP Token - Metadata service request failed: %v", err)
		}
		return "", errors.Errorf("failed to contact GCP metadata service: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		if c.logger != nil {
			c.logger.Logf("GCP Token - Failed to read response body: %v", err)
		}
		return "", errors.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if c.logger != nil {
			c.logger.Logf("GCP Token - Metadata service returned status %d: %s", resp.StatusCode, string(bodyBytes))
		}
		return "", errors.Errorf("GCP metadata request failed: %s, status: %d, body: %s",
			tokenURL, resp.StatusCode, string(bodyBytes))
	}

	token := string(bodyBytes)
	if token == "" {
		if c.logger != nil {
			c.logger.Logf("GCP Token - Received empty token from metadata service")
		}
		return "", errors.Errorf("received empty token from GCP metadata service")
	}

	if c.logger != nil {
		tokenPreview := "empty"
		if len(token) > 10 {
			tokenPreview = fmt.Sprintf("%d chars, starts with: %s...", len(token), token[:10])
		}
		c.logger.Logf("GCP Token - Successfully retrieved token: %s", tokenPreview)
	}

	return token, nil
}

// getAccessToken retrieves a GCP access token from the metadata service
// Access tokens are needed for authenticating to GCP APIs like IAM Credentials
func (c *GCPClient) getAccessToken(ctx context.Context) (string, error) {
	// Request an access token with the necessary scopes for IAM operations
	// The IAM Service Account Credentials API requires the following scope:
	// https://www.googleapis.com/auth/cloud-platform OR https://www.googleapis.com/auth/iam
	// Adding both to ensure we have the necessary permissions
	scopes := "https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/iam"
	tokenURL := fmt.Sprintf("%sinstance/service-accounts/default/token?scopes=%s", gcpMetadataURL, scopes)

	if c.logger != nil {
		c.logger.Logf("GCP Access Token - Requesting access token with cloud-platform and iam scopes from metadata service: %s", tokenURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", errors.Errorf("failed to create access token request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if c.logger != nil {
			c.logger.Logf("GCP Access Token - Metadata service request failed: %v", err)
		}
		return "", errors.Errorf("failed to contact GCP metadata service for access token: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		if c.logger != nil {
			c.logger.Logf("GCP Access Token - Failed to read response body: %v", err)
		}
		return "", errors.Errorf("failed to read access token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if c.logger != nil {
			c.logger.Logf("GCP Access Token - Metadata service returned status %d: %s", resp.StatusCode, string(bodyBytes))
		}
		return "", errors.Errorf("GCP access token request failed: %s, status: %d, body: %s",
			tokenURL, resp.StatusCode, string(bodyBytes))
	}

	// Parse the JSON response to extract the access token
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		if c.logger != nil {
			c.logger.Logf("GCP Access Token - Failed to parse JSON response: %v", err)
		}
		return "", errors.Errorf("failed to parse access token response: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		if c.logger != nil {
			c.logger.Logf("GCP Access Token - Received empty access token from metadata service")
		}
		return "", errors.Errorf("received empty access token from GCP metadata service")
	}

	if c.logger != nil {
		tokenPreview := "empty"
		if len(tokenResponse.AccessToken) > 10 {
			tokenPreview = fmt.Sprintf("%d chars, starts with: %s...", len(tokenResponse.AccessToken), tokenResponse.AccessToken[:10])
		}
		c.logger.Logf("GCP Access Token - Successfully retrieved access token: %s (expires in %d seconds)", tokenPreview, tokenResponse.ExpiresIn)
	}

	return tokenResponse.AccessToken, nil
}

// getIdentityFromToken parses the token to extract identity information
func (c *GCPClient) getIdentityFromToken(ctx context.Context, token string) (*models.CloudIdentity, error) {
	// Use the IDToken library to validate and parse the token
	// This is a simplification - in a real implementation, we might want to parse without full validation
	// for efficiency, since the token just came from the metadata service
	validator, err := idtoken.NewValidator(ctx)
	if err != nil {
		return nil, errors.Errorf("failed to create token validator: %w", err)
	}

	payload, err := validator.Validate(ctx, token, "")
	if err != nil {
		return nil, errors.Errorf("failed to parse ID token: %w", err)
	}

	// Extract identity information
	projectID := ""
	instanceID := ""
	serviceAccount := ""
	zone := ""

	// Extract the project number/ID
	if val, ok := payload.Claims["google/compute_engine/project_number"].(string); ok {
		projectID = val
	} else if val, ok := payload.Claims["project_id"].(string); ok {
		projectID = val
	}

	// Extract the instance ID
	if val, ok := payload.Claims["google/compute_engine/instance_id"].(string); ok {
		instanceID = val
	} else {
		// For non-GCE resources, generate a placeholder
		instanceID = "non-gce-resource"
	}

	// Extract service account email
	if val, ok := payload.Claims["email"].(string); ok {
		serviceAccount = val
	}

	// Extract zone if present
	if val, ok := payload.Claims["google/compute_engine/zone"].(string); ok {
		zone = val
	}

	// Construct a more detailed identifier
	identifier := fmt.Sprintf("projects/%s/instances/%s", projectID, instanceID)
	if serviceAccount != "" {
		identifier += "/serviceAccounts/" + serviceAccount
	}

	resourceType := "instance"
	if strings.Contains(serviceAccount, "cloud-function") {
		resourceType = "function"
	} else if strings.Contains(serviceAccount, "app-engine") {
		resourceType = "appengine"
	}

	region := ""
	if zone != "" {
		// Extract region from zone (e.g., us-central1-a -> us-central1)
		parts := strings.Split(zone, "-")
		if len(parts) >= 3 {
			region = strings.Join(parts[:len(parts)-1], "-")
		}
	}

	// Prepare additional claims
	additionalClaims := make(map[string]string)
	for k, v := range payload.Claims {
		if str, ok := v.(string); ok {
			additionalClaims[k] = str
		}
	}

	return &models.CloudIdentity{
		Provider:         models.ProviderGCP,
		Identifier:       identifier,
		AccountID:        projectID,
		Region:           region,
		ResourceType:     resourceType,
		AdditionalClaims: additionalClaims,
	}, nil
}

// AssumeRole configures the provider to use a different service account
func (c *GCPClient) AssumeRole(roleIdentifier string) models.CloudProviderClient {
	newClient := c.copy()
	newClient.serviceAccountEmail = roleIdentifier
	return newClient
}
