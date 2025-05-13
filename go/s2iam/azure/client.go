package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/memsql/errors"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

const (
	// Azure metadata service URLs
	azureMetadataURL = "http://169.254.169.254/metadata/identity/oauth2/token"
	azureInstanceURL = "http://169.254.169.254/metadata/instance"

	// Azure constants
	azureAPIVersion     = "2018-02-01"
	azureResourceServer = "https://management.azure.com/"
)

// AzureClient implements the CloudProviderClient interface for Azure
type AzureClient struct {
	managedIdentityID string
	identity          *models.CloudIdentity
	detected          bool
	logger            models.Logger // Added logger field
	mu                sync.Mutex    // Added for concurrency safety
}

func (c *AzureClient) copy() *AzureClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &AzureClient{
		managedIdentityID: c.managedIdentityID,
		identity:          c.identity,
		detected:          c.detected,
		logger:            c.logger,
	}
}

// azureClient is a singleton instance for AzureClient
var azureClient = &AzureClient{}

// NewClient returns the Azure client singleton
func NewClient(logger models.Logger) models.CloudProviderClient {
	azureClient.mu.Lock()
	defer azureClient.mu.Unlock()

	azureClient.logger = logger
	return azureClient
}

// Detect tests if we are executing within Azure and if a managed identity is available
func (c *AzureClient) Detect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if detection was already performed successfully
	if c.detected {
		return nil
	}

	if c.logger != nil {
		c.logger.Logf("Azure Detection - Starting detection")
	}

	// Fast path: Check Azure environment variable
	if os.Getenv("AZURE_ENV") != "" {
		if c.logger != nil {
			c.logger.Logf("Azure Detection - Found AZURE_ENV environment variable")
		}
		c.detected = true
		return nil
	}

	// Try to access the Azure metadata service
	if c.logger != nil {
		c.logger.Logf("Azure Detection - Trying metadata service")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01", nil)
	if err != nil {
		if c.logger != nil {
			c.logger.Logf("Azure Detection - Failed to create request: %v", err)
		}
		return errors.Errorf("not running on Azure: %w", err)
	}

	req.Header.Set("Metadata", "true")

	// Use an HTTP client without a fixed timeout to respect the context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		if c.logger != nil {
			c.logger.Logf("Azure Detection - Metadata service unavailable: %v", err)
		}
		return errors.Errorf("not running on Azure: metadata service unavailable: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		if c.logger != nil {
			c.logger.Logf("Azure Detection - Metadata service returned status %d", resp.StatusCode)
		}
		return errors.Errorf("not running on Azure: metadata service returned status %d", resp.StatusCode)
	}

	// We've confirmed we're on Azure, now check if a managed identity is available
	if c.logger != nil {
		c.logger.Logf("Azure Detection - Checking for managed identity")
	}

	// Try to get a token to verify identity is available
	tokenURL := fmt.Sprintf("%s?api-version=%s&resource=%s", azureMetadataURL, azureAPIVersion, azureResourceServer)
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		if c.logger != nil {
			c.logger.Logf("Azure Detection - Failed to create token request: %v", err)
		}
		return errors.Errorf("failed to create Azure token request: %w", err)
	}
	tokenReq.Header.Set("Metadata", "true")

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		if c.logger != nil {
			c.logger.Logf("Azure Detection - Token request failed: %v", err)
		}
		return models.ErrProviderDetectedNoIdentity.Errorf("Azure detected but no managed identity available: %s", err)
	}
	defer func() {
		_ = tokenResp.Body.Close()
	}()

	if tokenResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(tokenResp.Body)
		var errorResponse struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}

		if json.Unmarshal(bodyBytes, &errorResponse) == nil {
			if errorResponse.Error == "invalid_request" && strings.Contains(errorResponse.ErrorDescription, "Identity not found") {
				if c.logger != nil {
					c.logger.Logf("Azure Detection - No managed identity found")
				}
				return models.ErrProviderDetectedNoIdentity.Errorf("Azure detected but no managed identity available: invalid token response")
			}
		}

		if c.logger != nil {
			c.logger.Logf("Azure Detection - Token request returned status %d", tokenResp.StatusCode)
		}
		return models.ErrProviderDetectedNoIdentity.Errorf("Azure detected but managed identity check failed: %d", tokenResp.StatusCode)
	}

	// We've confirmed we're on Azure and have a managed identity
	c.detected = true
	if c.logger != nil {
		c.logger.Logf("Azure Detection - Successfully detected Azure environment with managed identity")
	}
	return nil
}

// GetType returns the cloud provider type
func (c *AzureClient) GetType() models.CloudProviderType {
	return models.ProviderAzure
}

// GetIdentityHeaders returns the headers needed to authenticate with the SingleStore auth service
func (c *AzureClient) GetIdentityHeaders(ctx context.Context, additionalParams map[string]string) (map[string]string, *models.CloudIdentity, error) {
	c.mu.Lock()
	detected := c.detected
	managedIdentityID := c.managedIdentityID
	logger := c.logger
	c.mu.Unlock()

	if !detected {
		return nil, nil, errors.WithStack(models.ErrProviderNotDetected)
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
		// Continue normally
	}

	url := fmt.Sprintf("%s?api-version=%s&resource=%s", azureMetadataURL, azureAPIVersion, azureResourceServer)

	// Use custom resource if provided in additionalParams
	if customResource, ok := additionalParams["azure_resource"]; ok && customResource != "" {
		url = fmt.Sprintf("%s?api-version=%s&resource=%s", azureMetadataURL, azureAPIVersion, customResource)
		if logger != nil {
			logger.Logf("Azure: Using custom resource audience: %s", customResource)
		}
	}

	// If a specific managed identity ID is provided, add it to the request
	if managedIdentityID != "" {
		url = fmt.Sprintf("%s&client_id=%s", url, managedIdentityID)
		if logger != nil {
			logger.Logf("Azure: Using specific managed identity ID: %s", managedIdentityID)
		}
	} else if logger != nil {
		logger.Logf("Azure: Using system-assigned managed identity")
	}

	if logger != nil {
		logger.Logf("Azure: Requesting token from URL: %s", url)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, errors.Errorf("failed to create Azure token request: %w", err)
	}

	// Azure requires this header for managed identity requests
	req.Header.Set("Metadata", "true")

	// Use an HTTP client without a fixed timeout to respect the context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, errors.Errorf("failed to get Azure Managed Identity token: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, errors.Errorf("failed to read Azure token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to parse the error for more information
		var errorResponse struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}

		jsonErr := json.Unmarshal(bodyBytes, &errorResponse)
		if jsonErr == nil && errorResponse.Error != "" {
			if logger != nil {
				logger.Logf("Azure: Token request failed with error: %s - %s",
					errorResponse.Error, errorResponse.ErrorDescription)
			}

			// Handle common error cases
			if errorResponse.Error == "invalid_request" && strings.Contains(errorResponse.ErrorDescription, "Identity not found") {
				if managedIdentityID != "" {
					return nil, nil, errors.Errorf("Azure token request failed: user-assigned managed identity with ID %s not found. Ensure the identity is assigned to this resource", managedIdentityID)
				} else {
					return nil, nil, errors.Errorf("Azure token request failed: no system-assigned managed identity found on this resource. Please assign a managed identity to this resource in the Azure portal")
				}
			}
		}

		return nil, nil, errors.Errorf("Azure token request failed: %d, %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		return nil, nil, errors.Errorf("failed to parse Azure token response: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		return nil, nil, errors.Errorf("received empty access token from Azure")
	}

	headers := map[string]string{
		"Authorization": "Bearer " + tokenResponse.AccessToken,
	}

	// Create identity object
	identity, err := c.getIdentityFromToken(ctx, tokenResponse.AccessToken)
	if err != nil {
		return headers, nil, errors.Errorf("got headers but failed to extract identity: %w", err) // Return headers even if identity extraction fails
	}

	return headers, identity, nil
}

// getIdentityFromToken parses the JWT token to extract identity information
func (c *AzureClient) getIdentityFromToken(ctx context.Context, tokenString string) (*models.CloudIdentity, error) {
	// Parse the token without validation to extract claims
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.Errorf("invalid token format")
	}

	// Decode the payload
	padded := parts[1]
	if len(padded)%4 != 0 {
		// Pad the base64 string if needed
		padded += strings.Repeat("=", 4-len(padded)%4)
	}

	payload, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		return nil, errors.Errorf("failed to decode token payload: %w", err)
	}

	// Parse the JSON payload
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.Errorf("failed to parse token claims: %w", err)
	}

	// Extract the principal ID (this is the identifier used by Azure for managed identities)
	var principalID string
	if oid, ok := claims["oid"].(string); ok {
		principalID = oid
	} else if sub, ok := claims["sub"].(string); ok {
		principalID = sub
	} else if appid, ok := claims["appid"].(string); ok {
		principalID = appid
	} else {
		return nil, errors.Errorf("failed to extract principal ID from token")
	}

	// Extract tenantID from issuer
	var tenantID string
	if iss, ok := claims["iss"].(string); ok {
		parts := strings.Split(iss, "/")
		for i, part := range parts {
			if part == "tokens" && i > 0 {
				tenantID = parts[i-1]
				break
			}
		}
	}

	// Get additional instance metadata if available
	resourceType := "unknown"
	region := ""

	// Extract resource type and region from token claims
	if mirid, ok := claims["xms_mirid"].(string); ok {
		parts := strings.Split(mirid, "/")
		if len(parts) > 2 {
			for i := 0; i < len(parts)-1; i++ {
				if parts[i] == "resourceGroups" && i+1 < len(parts) {
					// Extract region from resource group if possible
					rgParts := strings.Split(parts[i+1], "-")
					if len(rgParts) > 2 {
						region = rgParts[len(rgParts)-2] + "-" + rgParts[len(rgParts)-1]
					}
				}
				if parts[i] == "providers" && i+1 < len(parts) {
					resourceType = parts[i+1]
				}
			}
		}
	}

	// If region not in token, try to get it from instance metadata
	if region == "" {
		instanceReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
			azureInstanceURL+"?api-version=2021-02-01", nil)
		if err == nil {
			instanceReq.Header.Set("Metadata", "true")
			client := &http.Client{}
			resp, err := client.Do(instanceReq)
			if err == nil && resp.StatusCode == http.StatusOK {
				var instanceData map[string]interface{}
				if json.NewDecoder(resp.Body).Decode(&instanceData) == nil {
					if compute, ok := instanceData["compute"].(map[string]interface{}); ok {
						if location, ok := compute["location"].(string); ok {
							region = location
						}
					}
				}
				_ = resp.Body.Close()
			}
		}
	}

	// Create additional claims map
	additionalClaims := make(map[string]string)
	for k, v := range claims {
		if str, ok := v.(string); ok {
			additionalClaims[k] = str
		}
	}

	return &models.CloudIdentity{
		Provider:         models.ProviderAzure,
		Identifier:       principalID,
		AccountID:        tenantID,
		Region:           region,
		ResourceType:     resourceType,
		AdditionalClaims: additionalClaims,
	}, nil
}

// AssumeRole configures the provider to use a different managed identity
func (c *AzureClient) AssumeRole(roleIdentifier string) models.CloudProviderClient {
	newClient := c.copy()
	newClient.managedIdentityID = roleIdentifier
	return newClient
}
