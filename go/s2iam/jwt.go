package s2iam

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/memsql/errors"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

const (
	// defaultServer is the default authentication server endpoint
	defaultServer = "https://authsvc.singlestore.com/auth/iam/:jwtType"
)

// JWTOptions are used to configure how to get JWTs
type JWTOption interface {
	applyJWTOption(*jwtOptions)
}

// Implementation struct for JWT options
type jwtOption func(*jwtOptions)

func (o jwtOption) applyJWTOption(opts *jwtOptions) {
	o(opts)
}

// jwtOptions holds the options for the getJWT function
type jwtOptions struct {
	detectProviderOptions
	JWTType              JWTType
	WorkspaceGroupID     string
	ServerURL            string
	Provider             models.CloudProviderClient
	AdditionalParams     map[string]string
	AssumeRoleIdentifier string
}

// WithServerURL sets the authentication server URL
func WithServerURL(serverURL string) JWTOption {
	return jwtOption(func(o *jwtOptions) {
		o.ServerURL = serverURL
	})
}

// WithProvider sets a specific cloud provider client to use
func WithProvider(provider models.CloudProviderClient) JWTOption {
	return jwtOption(func(o *jwtOptions) {
		o.Provider = provider
	})
}

// WithGCPAudience sets the GCP audience for identity token requests
func WithGCPAudience(audience string) JWTOption {
	return jwtOption(func(o *jwtOptions) {
		o.AdditionalParams["audience"] = audience
	})
}

// WithAssumeRole sets the role identifier to assume (if there is one)
func WithAssumeRole(roleIdentifier string) JWTOption {
	return jwtOption(func(o *jwtOptions) {
		o.AssumeRoleIdentifier = roleIdentifier
	})
}

// processJWTOptions processes JWT options and extracts provider options
func processJWTOptions(jwtOpts jwtOptions, opts ...JWTOption) jwtOptions {
	if jwtOpts.AdditionalParams == nil {
		jwtOpts.AdditionalParams = make(map[string]string)
	}

	//nolint:staticcheck // QF1008: could remove embedded field "detectProviderOptions" from selector
	if jwtOpts.detectProviderOptions.timeout == 0 {
		//nolint:staticcheck // QF1008: could remove embedded field "detectProviderOptions" from selector
		jwtOpts.detectProviderOptions.timeout = defaultTimeout
	}

	for _, opt := range opts {
		// Apply to both option types
		opt.applyJWTOption(&jwtOpts)
	}

	return jwtOpts
}

// getJWT retrieves a JWT from the authentication server using cloud provider identity
func getJWT(ctx context.Context, defaultOpts jwtOptions, opts []JWTOption) (string, error) {
	jwtOpts := processJWTOptions(defaultOpts, opts...)

	if jwtOpts.ServerURL == "" {
		return "", errors.New("server URL is required")
	}

	// Auto-detect provider if not specified
	if jwtOpts.Provider == nil {
		var err error
		jwtOpts.Provider, err = detectProviderImpl(ctx, jwtOpts.detectProviderOptions)
		if err != nil {
			return "", errors.Errorf("failed to detect cloud provider: %w", err)
		}
	}

	// Create provider with assumed role if needed
	provider := jwtOpts.Provider
	if jwtOpts.AssumeRoleIdentifier != "" {
		provider = provider.AssumeRole(jwtOpts.AssumeRoleIdentifier)
	}

	identityHeaders, identity, err := provider.GetIdentityHeaders(ctx, jwtOpts.AdditionalParams)
	if err != nil {
		return "", errors.Errorf("failed to get identity headers: %w", err)
	}

	// Construct the URL
	targetURL := jwtOpts.ServerURL
	targetURL = strings.ReplaceAll(targetURL, ":cloudProvider", string(identity.Provider))
	targetURL = strings.ReplaceAll(targetURL, ":jwtType", string(jwtOpts.JWTType))

	uri, err := url.Parse(targetURL)
	if err != nil {
		return "", errors.Errorf("invalid server URL: %w", err)
	}

	// Add query parameters
	q := uri.Query()
	if jwtOpts.JWTType == DatabaseAccessJWT && jwtOpts.WorkspaceGroupID != "" {
		q.Add("workspaceGroupID", jwtOpts.WorkspaceGroupID)
	}
	uri.RawQuery = q.Encode()

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), nil)
	if err != nil {
		return "", errors.Errorf("error creating request: %w", err)
	}

	// Add identity headers
	for key, value := range identityHeaders {
		req.Header.Set(key, value)
	}

	// Send request
	httpClient := &http.Client{
		Timeout: 10 * time.Second, // Default HTTP client timeout
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", errors.Errorf("error calling authentication server: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Process response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("authentication server returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		JWT string `json:"jwt"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return "", errors.Errorf("cannot parse response: %w", err)
	}

	if response.JWT == "" {
		return "", errors.New("received empty JWT from server")
	}

	return response.JWT, nil
}

// GetDatabaseJWT retrieves a database JWT from the authentication server
func GetDatabaseJWT(ctx context.Context, workspaceGroupID string, opts ...JWTOption) (string, error) {
	if workspaceGroupID == "" {
		return "", errors.New("workspaceGroupID is required for database JWT")
	}

	return getJWT(ctx, jwtOptions{
		JWTType:          DatabaseAccessJWT,
		WorkspaceGroupID: workspaceGroupID,
		ServerURL:        defaultServer,
	}, opts)
}

// GetAPIJWT retrieves an API JWT from the authentication server
func GetAPIJWT(ctx context.Context, opts ...JWTOption) (string, error) {
	return getJWT(ctx, jwtOptions{
		JWTType:   APIGatewayAccessJWT,
		ServerURL: defaultServer,
	}, opts)
}
