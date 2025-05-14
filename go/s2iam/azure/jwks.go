package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/memsql/errors"
	"github.com/muir/gwrap"
)

const (
	// JWT cache TTL - we cache JWKs to avoid frequent HTTP requests
	jwksCacheTTL = time.Hour

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

// jwksManager handles fetching and caching of JWKS (JSON Web Key Sets)
type jwksManager struct {
	tenant       string
	jwks         jwkset.Storage
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
	}
}

// getKey retrieves a signing key by ID, refreshing the cache if needed
func (m *jwksManager) getKey(ctx context.Context, kid string) (any, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Check cache first (read lock)
	jwk, notExpired, err := func() (jwkset.JWK, bool, error) {
		m.mutex.RLock()
		defer m.mutex.RUnlock()
		if m.jwks == nil {
			return jwkset.JWK{}, false, jwkset.ErrKeyNotFound
		}
		jwk, err := m.jwks.KeyRead(ctx, kid)
		return jwk, time.Since(m.lastRefresh) <= jwksCacheTTL, err
	}()
	if err == nil && notExpired {
		return jwk.Key(), nil
	}

	// Cache miss or expired, refresh the keys (write lock)
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Double-check after acquiring write lock
	if m.jwks != nil {
		jwk, err := m.jwks.KeyRead(ctx, kid)
		if err == nil && time.Since(m.lastRefresh) <= jwksCacheTTL {
			return jwk.Key(), nil
		}
	}

	// Fetch the OIDC config to get the JWKS URI
	oidcConfig, err := fetchOIDCConfig(ctx, m.oidcEndpoint)
	if err != nil {
		return nil, errors.Errorf("failed to fetch OIDC config: %w", err)
	}

	jwks, err := jwkset.NewDefaultHTTPClientCtx(ctx, []string{oidcConfig.JwksURI})
	if err != nil {
		return nil, errors.Errorf("failed to fetch JWKS: %w", err)
	}

	m.jwks = jwks
	m.lastRefresh = time.Now()

	jwk, err = jwks.KeyRead(ctx, kid)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return jwk.Key(), nil
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
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("failed to fetch OIDC config, status: %d", resp.StatusCode)
	}

	var config oidcConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, errors.Errorf("failed to parse OIDC config: %w", err)
	}

	return &config, nil
}
