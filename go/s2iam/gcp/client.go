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
				resp.Body.Close()
			}
			if c.logger != nil {
				c.logger.Logf("GCP Detection - Metadata service available but no identity access")
			}
			return errors.WithStack(models.ErrProviderDetectedNoIdentity)
		}
		resp.Body.Close()

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
		resp.Body.Close()
		if c.logger != nil {
			c.logger.Logf("GCP Detection - Metadata service returned status %d", resp.StatusCode)
		}
		return errors.Errorf("not running on GCP: metadata service returned status %d", resp.StatusCode)
	}

	resp.Body.Close()
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
		// First get our own identity token for authentication
		selfToken, err := c.getIDToken(ctx, "https://iamcredentials.googleapis.com/")
		if err != nil {
			return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
		}

		// Use IAM API to impersonate the service account
		impersonationURL := fmt.Sprintf(
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken",
			serviceAccountEmail,
		)

		requestBody := fmt.Sprintf(`{"audience":"%s"}`, audience)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, impersonationURL, strings.NewReader(requestBody))
		if err != nil {
			return nil, nil, errors.Errorf("failed to create impersonation request: %w", err)
		}

		// Use our self token to authenticate the impersonation request
		req.Header.Set("Authorization", "Bearer "+selfToken)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, errors.Errorf("failed to impersonate service account: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return nil, nil, errors.Errorf("impersonation failed with status %d: %s", resp.StatusCode, string(bodyBytes))
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
			return headers, nil, errors.Errorf("got headers but failed to extract identity: %w", err) // Return headers even if identity extraction fails
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
		return headers, nil, errors.Errorf("got headers but failed to extract identity: %w", err) // Return headers even if identity extraction fails
	}

	return headers, identity, nil
}

// getIDToken retrieves a GCP identity token for the given audience
func (c *GCPClient) getIDToken(ctx context.Context, audience string) (string, error) {
	tokenURL := fmt.Sprintf("%sinstance/service-accounts/default/identity?audience=%s", gcpMetadataURL, audience)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", errors.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google") // Correct header for GCP metadata service

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Errorf("failed to contact GCP metadata service: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("GCP metadata request failed: %s, status: %d, body: %s",
			tokenURL, resp.StatusCode, string(bodyBytes))
	}

	token := string(bodyBytes)
	if token == "" {
		return "", errors.Errorf("received empty token from GCP metadata service")
	}

	return token, nil
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
