package verifier

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// Constants for cloud provider identifiers
const (
	ProviderAWS   = "aws"
	ProviderGCP   = "gcp"
	ProviderAzure = "azure"

	// Request timeout for external calls
	requestTimeout = 10 * time.Second

	// JWT cache TTL - we cache JWKs to avoid frequent HTTP requests
	jwksCacheTTL = 12 * time.Hour
)

// logDebug logs a debug-level message
func (v *Verifier) logDebug(format string, args ...interface{}) {
	if v.config.LogLevel >= LogLevelDebug && v.logger != nil {
		v.logger.Logf("[IAM] Debug: "+format, args...)
	}
}

// logInfo logs an info-level message
func (v *Verifier) logInfo(format string, args ...interface{}) {
	if v.config.LogLevel >= LogLevelInfo && v.logger != nil {
		v.logger.Logf("[IAM] "+format, args...)
	}
}

// logError logs an error message
func (v *Verifier) logError(format string, args ...interface{}) {
	if v.logger != nil {
		v.logger.Logf("[IAM] Error: "+format, args...)
	}
}

// VerifyRequest validates the cloud provider authentication in the request
// and returns the cloud identity information or an error.
func (v *Verifier) VerifyRequest(ctx context.Context, r *http.Request) (*CloudIdentity, error) {
	// Add timeout to context
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	// Check if request has AWS credentials
	if hasAWSHeaders(r) {
		v.logDebug("Detected AWS credentials in request")
		return v.verifyAWSRequest(ctx, r)
	}

	// Check if request has GCP credentials
	if hasGCPHeaders(r) {
		v.logDebug("Detected GCP credentials in request")
		return v.verifyGCPRequest(ctx, r)
	}

	// Check if request has Azure credentials
	if hasAzureHeaders(r) {
		v.logDebug("Detected Azure credentials in request")
		return v.verifyAzureRequest(ctx, r)
	}

	v.logError("Request does not contain valid cloud provider authentication headers")
	return nil, errors.New("request does not contain valid cloud provider authentication headers")
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
	return &jwksManager{
		tenant:       tenant,
		keysCache:    make(map[string]*rsa.PublicKey),
		oidcEndpoint: fmt.Sprintf(azureOIDCConfigFmt, tenant),
	}
}

// getKey retrieves a signing key by ID, refreshing the cache if needed
func (m *jwksManager) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
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

// OIDCConfig represents the OpenID Connect configuration
type OIDCConfig struct {
	Issuer   string `json:"issuer"`
	JwksURI  string `json:"jwks_uri"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// fetchOIDCConfig fetches the OpenID Connect configuration
func fetchOIDCConfig(ctx context.Context, endpoint string) (*OIDCConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch OIDC config, status: %d", resp.StatusCode)
	}

	var config OIDCConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// fetchJWKS fetches the JSON Web Key Set
func fetchJWKS(ctx context.Context, jwksURI string) (*JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS, status: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	return &jwks, nil
}

// jwkToRSAPublicKey converts a JWK to an RSA public key
func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
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
