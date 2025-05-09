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
)

const (
	// defaultServer is the default authentication server endpoint
	defaultServer = "https://auth.singlestore.com/auth/iam/:jwtType"

	// gcpDefaultAudience is the default audience for GCP identity token requests
	gcpDefaultAudience = "https://auth.singlestore.com"
)

// JWTType represents the type of JWT requested from the authentication service
type JWTType string

const (
	// DatabaseAccessJWT is used to request a JWT for accessing the database
	DatabaseAccessJWT JWTType = "database"

	// APIGatewayAccessJWT is used to request a JWT for accessing the API gateway
	APIGatewayAccessJWT JWTType = "api"
)

// JWTOption is a function that sets an option on the jwtOptions struct
type JWTOption func(*jwtOptions)

// jwtOptions holds the options for the getJWT function
type jwtOptions struct {
	JWTType              JWTType
	WorkspaceGroupID     string
	ServerURL            string
	Provider             CloudProviderClient
	AdditionalParams     map[string]string
	AssumeRoleIdentifier string
	Timeout              time.Duration
}

// WithServerURL sets the authentication server URL
func WithServerURL(serverURL string) JWTOption {
	return func(o *jwtOptions) {
		o.ServerURL = serverURL
	}
}

// WithProvider sets a specific cloud provider client to use
func WithProvider(provider CloudProviderClient) JWTOption {
	return func(o *jwtOptions) {
		o.Provider = provider
	}
}

// WithGCPAudience sets the GCP audience for identity token requests
func WithGCPAudience(audience string) JWTOption {
	return func(o *jwtOptions) {
		if o.AdditionalParams == nil {
			o.AdditionalParams = make(map[string]string)
		}
		o.AdditionalParams["audience"] = audience
	}
}

// WithAssumeRole sets the role identifier to assume
// (Role ARN for AWS, service account email for GCP, or managed identity ID for Azure)
func WithAssumeRole(roleIdentifier string) JWTOption {
	return func(o *jwtOptions) {
		o.AssumeRoleIdentifier = roleIdentifier
	}
}

// WithTimeout sets the request timeout
func WithTimeout(timeout time.Duration) JWTOption {
	return func(o *jwtOptions) {
		o.Timeout = timeout
	}
}

// getJWT retrieves a JWT from the authentication server using cloud provider identity
func getJWT(ctx context.Context, options jwtOptions) (string, error) {
	if options.Timeout == 0 {
		options.Timeout = 15 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	if options.ServerURL == "" {
		return "", errors.New("server URL is required")
	}

	// Auto-detect provider if not specified
	if options.Provider == nil {
		var err error
		options.Provider, err = DetectProvider(ctx, 5*time.Second)
		if err != nil {
			return "", errors.Errorf("failed to detect cloud provider: %w", err)
		}
	}

	// Create provider with assumed role if needed
	provider := options.Provider
	if options.AssumeRoleIdentifier != "" {
		provider = provider.AssumeRole(options.AssumeRoleIdentifier)
	}

	// Get identity headers
	if options.AdditionalParams == nil {
		options.AdditionalParams = make(map[string]string)
	}

	identityHeaders, identity, err := provider.GetIdentityHeaders(ctx, options.AdditionalParams)
	if err != nil {
		return "", errors.Errorf("failed to get identity headers: %w", err)
	}

	// Construct the URL
	targetURL := options.ServerURL
	targetURL = strings.ReplaceAll(targetURL, ":cloudProvider", string(identity.Provider))
	targetURL = strings.ReplaceAll(targetURL, ":jwtType", string(options.JWTType))

	uri, err := url.Parse(targetURL)
	if err != nil {
		return "", errors.Errorf("invalid server URL: %w", err)
	}

	// Add query parameters
	q := uri.Query()
	if options.JWTType == DatabaseAccessJWT && options.WorkspaceGroupID != "" {
		q.Add("workspaceGroupID", options.WorkspaceGroupID)
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
		Timeout: 10 * time.Second,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", errors.Errorf("error calling authentication server: %w", err)
	}
	defer resp.Body.Close()

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
// If a provider is not specified using WithProvider, one will be auto-detected
func GetDatabaseJWT(ctx context.Context, workspaceGroupID string, opts ...JWTOption) (string, error) {
	if workspaceGroupID == "" {
		return "", errors.New("workspaceGroupID is required for database JWT")
	}

	// Start with default options
	options := jwtOptions{
		JWTType:          DatabaseAccessJWT,
		WorkspaceGroupID: workspaceGroupID,
		ServerURL:        defaultServer,
	}

	// Apply user options
	for _, opt := range opts {
		opt(&options)
	}

	return getJWT(ctx, options)
}

// GetAPIJWT retrieves an API JWT from the authentication server
// If a provider is not specified using WithProvider, one will be auto-detected
func GetAPIJWT(ctx context.Context, opts ...JWTOption) (string, error) {
	// Start with default options
	options := jwtOptions{
		JWTType:   APIGatewayAccessJWT,
		ServerURL: defaultServer,
	}

	// Apply user options
	for _, opt := range opts {
		opt(&options)
	}

	return getJWT(ctx, options)
}
