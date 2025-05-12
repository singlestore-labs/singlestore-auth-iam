package s2iam

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// Azure metadata service URLs
	azureMetadataURL = "http://169.254.169.254/metadata/identity/oauth2/token"
	azureInstanceURL = "http://169.254.169.254/metadata/instance"

	// Azure constants
	azureAPIVersion     = "2018-02-01"
	azureResourceServer = "https://management.azure.com/"

	// Azure OIDC well-known configuration
	azureOIDCConfigFmt = "https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration"
	defaultAzureTenant = "common"

	// JWT cache TTL - we cache JWKs to avoid frequent HTTP requests
	jwksCacheTTL = 12 * time.Hour
)

// oidcConfig represents the OpenID Connect configuration
type oidcConfig struct {
	Issuer   string `json:"issuer"`
	JwksURI  string `json:"jwks_uri"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
}

// jwks represents a JSON Web Key Set
type jwks struct {
	Keys []jwk `json:"keys"`
}

// jwk represents a JSON Web Key
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// AzureClient implements the CloudProviderClient interface for Azure
type AzureClient struct {
	managedIdentityID string
	identity          *CloudIdentity
	detected          bool
	logger            Logger     // Added logger field
	mu                sync.Mutex // Added for concurrency safety
}

// azureClient is a singleton instance for AzureClient
var azureClient = &AzureClient{}

// NewAzureClient returns the Azure client singleton
func NewAzureClient(logger Logger) CloudProviderClient {
	azureClient.mu.Lock()
	defer azureClient.mu.Unlock()

	azureClient.logger = logger
	return azureClient
}

// Detect tests if we are executing within Azure
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
		return fmt.Errorf("not running on Azure: %w", err)
	}

	req.Header.Set("Metadata", "true")

	// Use an HTTP client without a fixed timeout to respect the context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		if c.logger != nil {
			c.logger.Logf("Azure Detection - Metadata service unavailable: %v", err)
		}
		return fmt.Errorf("not running on Azure: metadata service unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if c.logger != nil {
			c.logger.Logf("Azure Detection - Metadata service returned status %d", resp.StatusCode)
		}
		return fmt.Errorf("not running on Azure: metadata service returned status %d", resp.StatusCode)
	}

	// We've confirmed we're on Azure
	c.detected = true
	if c.logger != nil {
		c.logger.Logf("Azure Detection - Successfully detected Azure environment")
	}
	return nil
}

// checkIdentityAvailability verifies that a managed identity is available and can be used
// This should be called after Detect() confirms we're on Azure
func (c *AzureClient) checkIdentityAvailability(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.detected {
		return ErrProviderNotDetected
	}

	if c.logger != nil {
		c.logger.Logf("Azure - Checking for managed identity")
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Continue normally
	}

	// Try to get an identity token with a simple resource that should be widely accessible
	url := fmt.Sprintf("%s?api-version=%s&resource=%s",
		azureMetadataURL, azureAPIVersion, azureResourceServer)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create identity check request: %w", err)
	}

	req.Header.Set("Metadata", "true")

	// Use an HTTP client without a fixed timeout to respect the context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check identity availability: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body for error details
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// Try to parse the error response
		var errorResponse struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}

		if err := json.Unmarshal(bodyBytes, &errorResponse); err == nil &&
			errorResponse.Error == "invalid_request" &&
			strings.Contains(errorResponse.ErrorDescription, "Identity not found") {
			return errors.New("no managed identity assigned to this resource - please assign a managed identity in the Azure portal")
		}

		return fmt.Errorf("managed identity check failed: status %d, response: %s",
			resp.StatusCode, string(bodyBytes))
	}

	if c.logger != nil {
		c.logger.Logf("Azure - Managed identity available and working")
	}
	return nil
}

// GetType returns the cloud provider type
func (c *AzureClient) GetType() CloudProviderType {
	return ProviderAzure
}

// GetIdentityHeaders returns the headers needed to authenticate with the SingleStore auth service
func (c *AzureClient) GetIdentityHeaders(ctx context.Context, additionalParams map[string]string) (map[string]string, *CloudIdentity, error) {
	c.mu.Lock()
	detected := c.detected
	managedIdentityID := c.managedIdentityID
	logger := c.logger
	c.mu.Unlock()

	if !detected {
		return nil, nil, ErrProviderNotDetected
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
		return nil, nil, fmt.Errorf("failed to create Azure token request: %w", err)
	}

	// Azure requires this header for managed identity requests
	req.Header.Set("Metadata", "true")

	// Use an HTTP client without a fixed timeout to respect the context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get Azure Managed Identity token: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read Azure token response: %w", err)
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
					return nil, nil, fmt.Errorf("Azure token request failed: user-assigned managed identity with ID %s not found. Ensure the identity is assigned to this resource", managedIdentityID)
				} else {
					return nil, nil, errors.New("Azure token request failed: no system-assigned managed identity found on this resource. Please assign a managed identity to this resource in the Azure portal")
				}
			}
		}

		return nil, nil, fmt.Errorf("Azure token request failed: %d, %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		return nil, nil, fmt.Errorf("failed to parse Azure token response: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		return nil, nil, errors.New("received empty access token from Azure")
	}

	headers := map[string]string{
		"Authorization": "Bearer " + tokenResponse.AccessToken,
	}

	// Create identity object
	identity, err := c.getIdentityFromToken(ctx, tokenResponse.AccessToken)
	if err != nil {
		return headers, nil, fmt.Errorf("got headers but failed to extract identity: %w", err) // Return headers even if identity extraction fails
	}

	return headers, identity, nil
}

// getIdentityFromToken parses the JWT token to extract identity information
func (c *AzureClient) getIdentityFromToken(ctx context.Context, tokenString string) (*CloudIdentity, error) {
	// Simple token parsing logic - in practice, we'd use a JWT library
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	// Decode the payload
	padded := parts[1]
	if len(padded)%4 != 0 {
		// Pad the base64 string if needed
		padded += strings.Repeat("=", 4-len(padded)%4)
	}

	payload, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	// Parse the JSON payload
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
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
		return nil, errors.New("failed to extract principal ID from token")
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
				resp.Body.Close()
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

	return &CloudIdentity{
		Provider:         ProviderAzure,
		Identifier:       principalID,
		AccountID:        tenantID,
		Region:           region,
		ResourceType:     resourceType,
		AdditionalClaims: additionalClaims,
	}, nil
}

// AssumeRole configures the provider to use a different managed identity
func (c *AzureClient) AssumeRole(roleIdentifier string) CloudProviderClient {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create a new client to avoid modifying the original
	newClient := &AzureClient{
		identity:          c.identity,
		detected:          c.detected,
		managedIdentityID: roleIdentifier,
		logger:            c.logger,
	}

	return newClient
}

// fetchOIDCConfig fetches the OpenID Connect configuration
func fetchOIDCConfig(ctx context.Context, endpoint string) (*oidcConfig, error) {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Continue normally
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC config request: %w", err)
	}

	// Use an HTTP client without a fixed timeout to respect the context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch OIDC config, status: %d", resp.StatusCode)
	}

	var config oidcConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC config: %w", err)
	}

	return &config, nil
}

// fetchJWKS fetches the JSON Web Key Set
func fetchJWKS(ctx context.Context, jwksURI string) (*jwks, error) {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Continue normally
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	// Use an HTTP client without a fixed timeout to respect the context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS, status: %d", resp.StatusCode)
	}

	var jwksResult jwks
	if err := json.NewDecoder(resp.Body).Decode(&jwksResult); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return &jwksResult, nil
}

// jwkToRSAPublicKey converts a JWK to an RSA public key
func jwkToRSAPublicKey(jwk jwk) (*rsa.PublicKey, error) {
	// Decode modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key modulus: %w", err)
	}

	// Decode exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key exponent: %w", err)
	}

	// Convert bytes to big integers
	n := new(big.Int).SetBytes(nBytes)

	// Convert exponent bytes to int
	var eInt int
	for i, b := range eBytes {
		eInt += int(b) << (8 * (len(eBytes) - i - 1))
	}

	// Create RSA public key
	return &rsa.PublicKey{
		N: n,
		E: eInt,
	}, nil
}

// jwksManager handles fetching and caching of JWKS (JSON Web Key Sets)
type jwksManager struct {
	tenant       string
	keysCache    map[string]*rsa.PublicKey
	lastRefresh  time.Time
	mutex        sync.RWMutex
	oidcEndpoint string
}

// newJWKSManager creates a new JWKS manager for the specified tenant
func newJWKSManager(tenant string) *jwksManager {
	oidcEndpoint := fmt.Sprintf(azureOIDCConfigFmt, tenant)
	return &jwksManager{
		tenant:       tenant,
		keysCache:    make(map[string]*rsa.PublicKey),
		oidcEndpoint: oidcEndpoint,
	}
}

// getKey retrieves a signing key by ID, refreshing the cache if needed
func (m *jwksManager) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Continue normally
	}

	// Check cache first (read lock)
	m.mutex.RLock()
	key, found := m.keysCache[kid]
	cacheExpired := time.Since(m.lastRefresh) > jwksCacheTTL
	m.mutex.RUnlock()

	if found && !cacheExpired {
		return key, nil
	}

	// Cache miss or expired, refresh the keys (write lock)
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Double-check after acquiring write lock
	if key, found = m.keysCache[kid]; found && time.Since(m.lastRefresh) <= jwksCacheTTL {
		return key, nil
	}

	// Fetch the OIDC config to get the JWKS URI
	oidcConfig, err := fetchOIDCConfig(ctx, m.oidcEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC config: %w", err)
	}

	// Fetch the JWKS
	jwks, err := fetchJWKS(ctx, oidcConfig.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Parse and cache all keys
	m.keysCache = make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty == "RSA" {
			key, err := jwkToRSAPublicKey(jwk)
			if err != nil {
				continue // Skip invalid keys
			}
			m.keysCache[jwk.Kid] = key
		}
	}

	m.lastRefresh = time.Now()

	// Return the requested key
	key, found = m.keysCache[kid]
	if !found {
		return nil, fmt.Errorf("key ID %s not found in JWKS", kid)
	}

	return key, nil
}

// parseToken parses a JWT token string without validation
func parseToken(tokenString string) (*struct {
	Header map[string]interface{}
	Claims map[string]interface{}
}, error,
) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	// Decode header
	headerJSON, err := decodeBase64UrlSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse token header: %w", err)
	}

	// Decode payload
	payloadJSON, err := decodeBase64UrlSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	return &struct {
		Header map[string]interface{}
		Claims map[string]interface{}
	}{
		Header: header,
		Claims: claims,
	}, nil
}

// decodeBase64UrlSegment properly decodes a Base64URL encoded string
func decodeBase64UrlSegment(segment string) ([]byte, error) {
	// Add padding if needed
	if len(segment)%4 != 0 {
		segment += strings.Repeat("=", 4-len(segment)%4)
	}

	// JWT uses base64url encoding
	return base64.URLEncoding.DecodeString(segment)
}

// validateToken validates a JWT token using the given public key
func validateToken(tokenString string, key interface{}) bool {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false
	}

	parsedToken, err := parseToken(tokenString)
	if err != nil {
		return false
	}

	if exp, ok := parsedToken.Claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return false
		}
	} else {
		return false
	}

	if nbf, ok := parsedToken.Claims["nbf"].(float64); ok {
		if time.Now().Unix() < int64(nbf) {
			return false
		}
	}

	alg, ok := parsedToken.Header["alg"].(string)
	if !ok {
		return false
	}

	signedContent := parts[0] + "." + parts[1]
	signature, err := decodeBase64UrlSegment(parts[2])
	if err != nil {
		return false
	}

	switch {
	case strings.HasPrefix(alg, "RS"):
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}

		var hash crypto.Hash
		switch alg {
		case "RS256":
			hash = crypto.SHA256
		case "RS384":
			hash = crypto.SHA384
		case "RS512":
			hash = crypto.SHA512
		default:
			return false
		}

		hasher := hash.New()
		hasher.Write([]byte(signedContent))
		hashed := hasher.Sum(nil)

		return rsa.VerifyPKCS1v15(rsaKey, hash, hashed, signature) == nil

	case strings.HasPrefix(alg, "ES"):
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return false
		}

		var hash crypto.Hash
		var curveBits int
		switch alg {
		case "ES256":
			hash = crypto.SHA256
			curveBits = 256
		case "ES384":
			hash = crypto.SHA384
			curveBits = 384
		case "ES512":
			hash = crypto.SHA512
			curveBits = 521
		default:
			return false
		}

		hasher := hash.New()
		hasher.Write([]byte(signedContent))
		hashed := hasher.Sum(nil)

		sigLen := len(signature)
		if sigLen != 2*curveBits/8 {
			return false
		}

		r := new(big.Int).SetBytes(signature[:sigLen/2])
		s := new(big.Int).SetBytes(signature[sigLen/2:])

		return ecdsa.Verify(ecKey, hashed, r, s)

	case strings.HasPrefix(alg, "HS"):
		secretKey, ok := key.([]byte)
		if !ok {
			return false
		}

		var hash func() hash.Hash
		switch alg {
		case "HS256":
			hash = sha256.New
		case "HS384":
			hash = sha512.New384
		case "HS512":
			hash = sha512.New
		default:
			return false
		}

		mac := hmac.New(hash, secretKey)
		mac.Write([]byte(signedContent))
		expected := mac.Sum(nil)

		return hmac.Equal(signature, expected)

	default:
		return false
	}
}

// extractPrincipalID extracts the principal ID from the token claims
func extractPrincipalID(claims map[string]interface{}) (string, error) {
	// Primary location: objectId/oid claim contains the principal ID
	if principalID, ok := claims["oid"].(string); ok {
		return principalID, nil
	}

	// Alternative location: subject claim may contain the principal ID
	if sub, ok := claims["sub"].(string); ok {
		return sub, nil
	}

	// Last resort: check appid
	if appID, ok := claims["appid"].(string); ok {
		return appID, nil
	}

	return "", errors.New("principal ID not found in Azure token")
}

// extractTenantFromIssuer extracts the tenant ID from the issuer URL
func extractTenantFromIssuer(issuer string) (string, error) {
	parts := strings.Split(issuer, "/")
	for i, part := range parts {
		if part == "tokens" && i > 0 {
			return parts[i-1], nil
		}
	}
	return "", errors.New("tenant ID not found in issuer URL")
}

// AzureVerifier implements the CloudProviderVerifier interface for Azure
type AzureVerifier struct {
	jwksManager      *jwksManager
	allowedAudiences []string
	tenant           string
	logger           Logger
	mu               sync.RWMutex // Added for concurrency safety
}

// azureVerifier is a singleton instance for AzureVerifier
var azureVerifier = &AzureVerifier{}

// NewAzureVerifier creates or configures the Azure verifier
func NewAzureVerifier(allowedAudiences []string, tenant string, logger Logger) CloudProviderVerifier {
	azureVerifier.mu.Lock()
	defer azureVerifier.mu.Unlock()

	if tenant == "" {
		tenant = defaultAzureTenant // Use the common endpoint by default
	}

	// Initialize JWKS manager if needed
	if azureVerifier.jwksManager == nil || azureVerifier.tenant != tenant {
		azureVerifier.jwksManager = newJWKSManager(tenant)
		azureVerifier.tenant = tenant
	}

	// Update configuration
	azureVerifier.allowedAudiences = allowedAudiences
	azureVerifier.logger = logger

	return azureVerifier
}

// HasHeaders returns true if the request has Azure authentication headers
func (v *AzureVerifier) HasHeaders(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	return strings.HasPrefix(authHeader, "Bearer ") && hasAzureMarkers(r)
}

// hasAzureMarkers checks for Azure-specific traits in the token
func hasAzureMarkers(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Perform a quick check without fully parsing the token
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	// Try to decode the payload
	padded := parts[1]
	if len(padded)%4 != 0 {
		padded += strings.Repeat("=", 4-len(padded)%4)
	}
	payload, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		return false
	}

	// Look for Azure-specific claims without fully parsing JSON
	return strings.Contains(string(payload), "microsoftonline.com") ||
		strings.Contains(string(payload), "windows.net")
}

// VerifyRequest validates Azure credentials and returns the identity
func (v *AzureVerifier) VerifyRequest(ctx context.Context, r *http.Request) (*CloudIdentity, error) {
	v.mu.RLock()
	logger := v.logger
	allowedAudiences := v.allowedAudiences
	jwksManager := v.jwksManager
	v.mu.RUnlock()

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Continue normally
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		if logger != nil {
			logger.Logf("Invalid Azure authentication header format")
		}
		return nil, errors.New("invalid Azure authentication header format")
	}

	// Extract the token from the Authorization header
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		if logger != nil {
			logger.Logf("Empty Azure token")
		}
		return nil, errors.New("empty Azure token")
	}

	// Parse without verifying to extract claims first
	token, err := parseToken(tokenString)
	if err != nil {
		if logger != nil {
			logger.Logf("Failed to parse Azure token: %v", err)
		}
		return nil, fmt.Errorf("failed to parse Azure token: %w", err)
	}

	// Extract claims
	if token.Claims == nil {
		if logger != nil {
			logger.Logf("Failed to parse Azure token claims")
		}
		return nil, errors.New("failed to parse Azure token claims")
	}

	// Get token issuer to determine tenant
	var issuer string
	if iss, ok := token.Claims["iss"].(string); ok {
		issuer = iss
	} else {
		if logger != nil {
			logger.Logf("Issuer claim missing from token")
		}
		return nil, errors.New("issuer claim missing from token")
	}

	// Check that it's an Azure token
	if !strings.Contains(issuer, "microsoftonline.com") && !strings.Contains(issuer, "windows.net") {
		if logger != nil {
			logger.Logf("Token not issued by Azure AD")
		}
		return nil, errors.New("token not issued by Azure AD")
	}

	if logger != nil {
		logger.Logf("Verifying Azure token from issuer: %s", issuer)
	}

	// Extract the kid (key ID) from the token header
	var kid string
	if token.Header["kid"] != nil {
		kid = token.Header["kid"].(string)
	} else {
		if logger != nil {
			logger.Logf("KID header missing from token")
		}
		return nil, errors.New("kid header missing from token")
	}

	// Get the appropriate key from JWKS
	key, err := jwksManager.getKey(ctx, kid)
	if err != nil {
		if logger != nil {
			logger.Logf("Failed to get Azure signing key: %v", err)
		}
		return nil, fmt.Errorf("failed to get Azure signing key: %w", err)
	}

	// Validate the token using the key
	if !validateToken(tokenString, key) {
		if logger != nil {
			logger.Logf("Azure token is invalid")
		}
		return nil, errors.New("Azure token is invalid")
	}

	// Verify audience claim against allowed audiences
	audience, _ := token.Claims["aud"].(string)
	audienceValid := false

	for _, allowedAudience := range allowedAudiences {
		if audience == allowedAudience || audience == "https://management.azure.com/" {
			audienceValid = true
			break
		}
	}

	if !audienceValid {
		if logger != nil {
			logger.Logf("Azure token has invalid audience: %s", audience)
		}
		return nil, errors.New("Azure token has invalid audience")
	}

	// Extract the principal ID
	principalID, err := extractPrincipalID(token.Claims)
	if err != nil {
		if logger != nil {
			logger.Logf("Failed to extract principal ID: %v", err)
		}
		return nil, fmt.Errorf("failed to extract principal ID: %w", err)
	}

	// Extract additional information
	tenantID, _ := extractTenantFromIssuer(issuer)
	resourceType := "unknown"
	region := ""

	// Extract resource type and region from the token
	if mirid, ok := token.Claims["xms_mirid"].(string); ok {
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

	// Prepare additional claims
	additionalClaims := make(map[string]string)
	for k, v := range token.Claims {
		if str, ok := v.(string); ok {
			additionalClaims[k] = str
		}
	}

	if logger != nil {
		logger.Logf("Successfully verified Azure identity: %s", principalID)
	}

	return &CloudIdentity{
		Provider:         ProviderAzure,
		Identifier:       principalID,
		AccountID:        tenantID,
		Region:           region,
		ResourceType:     resourceType,
		AdditionalClaims: additionalClaims,
	}, nil
}
