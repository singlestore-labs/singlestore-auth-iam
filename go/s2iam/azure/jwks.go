package azure

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/memsql/errors"
	"github.com/muir/gwrap"
)

const (
	// JWT cache TTL - we cache JWKs to avoid frequent HTTP requests
	jwksCacheTTL = 12 * time.Hour

	// Azure OIDC well-known configuration
	azureOIDCConfigFmt = "https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration"
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
	Keys []map[string]interface{} `json:"keys"`
}

// jwksManager handles fetching and caching of JWKS (JSON Web Key Sets)
type jwksManager struct {
	tenant       string
	keys         map[string]interface{} // Cache of parsed keys by kid
	lastRefresh  time.Time
	mutex        sync.RWMutex
	oidcEndpoint string
}

var managers gwrap.SyncMap[string, *jwksManager]

func getJWKSManager(tenant string) *jwksManager {
	m, ok := managers.Load(tenant)
	if ok {
		return m
	}
	m, _ = managers.LoadOrStore(tenant, newJWKSManager(tenant))
	return m
}

// newJWKSManager creates a new JWKS manager for the specified tenant
func newJWKSManager(tenant string) *jwksManager {
	oidcEndpoint := fmt.Sprintf(azureOIDCConfigFmt, tenant)
	return &jwksManager{
		tenant:       tenant,
		oidcEndpoint: oidcEndpoint,
		keys:         make(map[string]interface{}),
	}
}

// getKey retrieves a signing key by ID, refreshing the cache if needed
func (m *jwksManager) getKey(ctx context.Context, kid string) (interface{}, error) {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Continue normally
	}

	// Check cache first (read lock)
	m.mutex.RLock()
	key, found := m.keys[kid]
	cacheExpired := time.Since(m.lastRefresh) > jwksCacheTTL
	m.mutex.RUnlock()

	if found && !cacheExpired {
		return key, nil
	}

	// Cache miss or expired, refresh the keys (write lock)
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Double-check after acquiring write lock
	if key, found = m.keys[kid]; found && time.Since(m.lastRefresh) <= jwksCacheTTL {
		return key, nil
	}

	// Fetch the OIDC config to get the JWKS URI
	oidcConfig, err := fetchOIDCConfig(ctx, m.oidcEndpoint)
	if err != nil {
		return nil, errors.Errorf("failed to fetch OIDC config: %w", err)
	}

	// Fetch the JWKS
	jwks, err := fetchJWKS(ctx, oidcConfig.JwksURI)
	if err != nil {
		return nil, errors.Errorf("failed to fetch JWKS: %w", err)
	}

	// Parse and cache all keys
	m.keys = make(map[string]interface{})
	for _, jwk := range jwks.Keys {
		keyID, ok := jwk["kid"].(string)
		if !ok {
			continue
		}

		keyType, ok := jwk["kty"].(string)
		if !ok || keyType != "RSA" {
			continue
		}

		// Parse RSA public key from JWK
		key, err := parseRSAPublicKeyFromJWK(jwk)
		if err != nil {
			continue // Skip invalid keys
		}

		m.keys[keyID] = key
	}

	m.lastRefresh = time.Now()

	// Return the requested key
	key, found = m.keys[kid]
	if !found {
		return nil, errors.Errorf("key ID %s not found in JWKS", kid)
	}

	return key, nil
}

// parseRSAPublicKeyFromJWK converts a JWK to an RSA public key
func parseRSAPublicKeyFromJWK(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	// Extract modulus (n) and exponent (e)
	nStr, ok := jwk["n"].(string)
	if !ok {
		return nil, errors.Errorf("missing or invalid modulus (n) in JWK")
	}

	eStr, ok := jwk["e"].(string)
	if !ok {
		return nil, errors.Errorf("missing or invalid exponent (e) in JWK")
	}

	// Decode base64URL encoded values
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, errors.Errorf("failed to decode modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, errors.Errorf("failed to decode exponent: %w", err)
	}

	// Convert to big integers
	n := new(big.Int).SetBytes(nBytes)

	// Convert exponent bytes to int
	// For RSA public keys, 'e' is typically 65537 (0x10001) encoded as "AQAB"
	var e int
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
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
		return nil, errors.Errorf("failed to create JWKS request: %w", err)
	}

	// Use an HTTP client without a fixed timeout to respect the context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("failed to fetch JWKS, status: %d", resp.StatusCode)
	}

	var jwksResult jwks
	if err := json.NewDecoder(resp.Body).Decode(&jwksResult); err != nil {
		return nil, errors.Errorf("failed to parse JWKS: %w", err)
	}

	return &jwksResult, nil
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
		return nil, errors.Errorf("failed to create OIDC config request: %w", err)
	}

	// Use an HTTP client without a fixed timeout to respect the context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Errorf("failed to fetch OIDC config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("failed to fetch OIDC config, status: %d", resp.StatusCode)
	}

	var config oidcConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, errors.Errorf("failed to parse OIDC config: %w", err)
	}

	return &config, nil
}
