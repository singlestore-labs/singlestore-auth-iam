package s2iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

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
	identity            *CloudIdentity
	detected            bool
	mu                  sync.Mutex // Added for concurrency safety
}

// gcpClient is a singleton instance for GCPClient
var gcpClient = &GCPClient{}

// NewGCPClient returns the GCP client singleton
func NewGCPClient() CloudProviderClient {
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
		return nil
	}

	// Try to access the GCP metadata service
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		gcpMetadataURL+"instance/id", nil)
	if err != nil {
		return fmt.Errorf("not running on GCP: %w", err)
	}

	req.Header.Set("Metadata-Flavor", "Google")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("not running on GCP: metadata service unavailable: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("not running on GCP: metadata service returned status %d", resp.StatusCode)
	}

	resp.Body.Close()
	c.detected = true
	return nil
}

// GetType returns the cloud provider type
func (c *GCPClient) GetType() CloudProviderType {
	return ProviderGCP
}

// GetIdentityHeaders returns the headers needed to authenticate with the SingleStore auth service
func (c *GCPClient) GetIdentityHeaders(ctx context.Context, additionalParams map[string]string) (map[string]string, *CloudIdentity, error) {
	c.mu.Lock()
	detected := c.detected
	serviceAccountEmail := c.serviceAccountEmail
	c.mu.Unlock()

	if !detected {
		return nil, nil, ErrProviderNotDetected
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
			return nil, nil, fmt.Errorf("failed to get self identity token: %w", err)
		}

		// Use IAM API to impersonate the service account
		impersonationURL := fmt.Sprintf(
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken",
			serviceAccountEmail,
		)

		requestBody := fmt.Sprintf(`{"audience":"%s"}`, audience)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, impersonationURL, strings.NewReader(requestBody))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create impersonation request: %w", err)
		}

		// Use our self token to authenticate the impersonation request
		req.Header.Set("Authorization", "Bearer "+selfToken)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to impersonate service account: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return nil, nil, fmt.Errorf("impersonation failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var tokenResponse struct {
			Token string `json:"token"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
			return nil, nil, fmt.Errorf("failed to parse impersonation response: %w", err)
		}

		if tokenResponse.Token == "" {
			return nil, nil, errors.New("received empty token from impersonation service")
		}

		headers := map[string]string{
			"Authorization": "Bearer " + tokenResponse.Token,
		}

		// Create identity object
		identity, err := c.getIdentityFromToken(ctx, tokenResponse.Token)
		if err != nil {
			return headers, nil, fmt.Errorf("got headers but failed to extract identity: %w", err) // Return headers even if identity extraction fails
		}

		return headers, identity, nil
	}

	// Original implementation when no service account impersonation is needed
	idToken, err := c.getIDToken(ctx, audience)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get GCP ID token: %w", err)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + idToken,
	}

	// Create identity object
	identity, err := c.getIdentityFromToken(ctx, idToken)
	if err != nil {
		return headers, nil, fmt.Errorf("got headers but failed to extract identity: %w", err) // Return headers even if identity extraction fails
	}

	return headers, identity, nil
}

// getIDToken retrieves a GCP identity token for the given audience
func (c *GCPClient) getIDToken(ctx context.Context, audience string) (string, error) {
	tokenURL := fmt.Sprintf("%sinstance/service-accounts/default/identity?audience=%s", gcpMetadataURL, audience)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google") // Correct header for GCP metadata service

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to contact GCP metadata service: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GCP metadata request failed: %s, status: %d, body: %s",
			tokenURL, resp.StatusCode, string(bodyBytes))
	}

	token := string(bodyBytes)
	if token == "" {
		return "", errors.New("received empty token from GCP metadata service")
	}

	return token, nil
}

// getIdentityFromToken parses the token to extract identity information
func (c *GCPClient) getIdentityFromToken(ctx context.Context, token string) (*CloudIdentity, error) {
	// Use the IDToken library to validate and parse the token
	// This is a simplification - in a real implementation, we might want to parse without full validation
	// for efficiency, since the token just came from the metadata service
	validator, err := idtoken.NewValidator(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create token validator: %w", err)
	}

	payload, err := validator.Validate(ctx, token, "")
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
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

	return &CloudIdentity{
		Provider:         ProviderGCP,
		Identifier:       identifier,
		AccountID:        projectID,
		Region:           region,
		ResourceType:     resourceType,
		AdditionalClaims: additionalClaims,
	}, nil
}

// AssumeRole configures the provider to use a different service account
func (c *GCPClient) AssumeRole(roleIdentifier string) CloudProviderClient {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create a new client to avoid modifying the original
	newClient := &GCPClient{
		identity:            c.identity,
		detected:            c.detected,
		serviceAccountEmail: roleIdentifier,
	}

	return newClient
}

// GCPVerifier implements the CloudProviderVerifier interface for GCP
type GCPVerifier struct {
	validator        *idtoken.Validator
	allowedAudiences []string
	logLevel         int
	logger           Logger
	mu               sync.RWMutex // Added for concurrency safety
}

// gcpVerifier is a singleton instance for GCPVerifier
var gcpVerifier = &GCPVerifier{}

// NewGCPVerifier creates or configures the GCP verifier
func NewGCPVerifier(ctx context.Context, allowedAudiences []string, logger Logger, logLevel int) (CloudProviderVerifier, error) {
	gcpVerifier.mu.Lock()
	defer gcpVerifier.mu.Unlock()

	// Create a new validator if it doesn't exist or if contexts/configs have changed
	if gcpVerifier.validator == nil {
		validator, err := idtoken.NewValidator(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCP token validator: %w", err)
		}
		gcpVerifier.validator = validator
	}

	// Update configuration
	gcpVerifier.allowedAudiences = allowedAudiences
	if logger != nil {
		gcpVerifier.logger = logger
		gcpVerifier.logLevel = logLevel
	}

	return gcpVerifier, nil
}

// HasHeaders returns true if the request has GCP authentication headers
func (v *GCPVerifier) HasHeaders(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	return strings.HasPrefix(authHeader, "Bearer ") && !hasAzureMarkers(r)
}

// VerifyRequest validates GCP credentials and returns the identity
func (v *GCPVerifier) VerifyRequest(ctx context.Context, r *http.Request) (*CloudIdentity, error) {
	v.mu.RLock()
	validator := v.validator
	allowedAudiences := v.allowedAudiences
	logger := v.logger
	logLevel := v.logLevel
	v.mu.RUnlock()

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		if logger != nil && logLevel > 0 {
			logger.Logf("Invalid GCP authentication header format")
		}
		return nil, errors.New("invalid GCP authentication header format")
	}

	// Extract the token from the Authorization header
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		if logger != nil && logLevel > 0 {
			logger.Logf("Empty GCP token")
		}
		return nil, errors.New("empty GCP token")
	}

	if logger != nil && logLevel > 1 {
		logger.Logf("Verifying GCP token with %d allowed audiences", len(allowedAudiences))
	}

	// Find a matching audience
	var validationErr error

	for _, audience := range allowedAudiences {
		payload, err := validator.Validate(ctx, token, audience)
		if err == nil {
			// Extract the identity information from the token payload
			projectID, instanceID, serviceAccount, zone, err := v.extractIdentifiers(payload)
			if err != nil {
				if logger != nil && logLevel > 0 {
					logger.Logf("Failed to extract identifiers from token: %v", err)
				}
				return nil, err
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

			if logger != nil && logLevel > 0 {
				logger.Logf("Successfully verified GCP identity: %s", identifier)
			}

			return &CloudIdentity{
				Provider:         ProviderGCP,
				Identifier:       identifier,
				AccountID:        projectID,
				Region:           region,
				ResourceType:     resourceType,
				AdditionalClaims: additionalClaims,
			}, nil
		}
		validationErr = err
	}

	if logger != nil && logLevel > 0 {
		logger.Logf("Failed to validate GCP token: %v", validationErr)
	}
	return nil, fmt.Errorf("invalid GCP token for allowed audiences: %w", validationErr)
}

// extractIdentifiers extracts project and instance identifiers from the token payload
func (v *GCPVerifier) extractIdentifiers(payload *idtoken.Payload) (projectID, instanceID, serviceAccount, zone string, err error) {
	// Extract the project number
	if val, ok := payload.Claims["google/compute_engine/project_number"].(string); ok {
		projectID = val
	} else if val, ok := payload.Claims["project_id"].(string); ok {
		projectID = val
	} else {
		return "", "", "", "", errors.New("project identifier not found in GCP token")
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

	return projectID, instanceID, serviceAccount, zone, nil
}
