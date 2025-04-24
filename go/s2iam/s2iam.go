package s2iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	// Service endpoints and defaults
	defaultServer = "https://auth.singlestore.com/auth/iam/:jwtType"

	// Metadata service URLs
	awsMetadataURL   = "http://169.254.169.254/latest/meta-data/"
	gcpMetadataURL   = "http://metadata.google.internal/computeMetadata/v1/"
	azureMetadataURL = "http://169.254.169.254/metadata/identity/oauth2/token"

	// Azure constants
	azureAPIVersion     = "2018-02-01"
	azureResourceServer = "https://management.azure.com/"

	// GCP constants - this should be configured by the user for their specific deployment
	gcpDefaultAudience = "https://auth.singlestore.com"
)

// JWTType represents the type of JWT requested. This is used to tell
// the external authentication service what kind of JWT we want.
type JWTType string

const (
	// DatabaseAccessJWT is used to request a JWT for accessing the database
	DatabaseAccessJWT JWTType = "database"

	// APIGatewayAccessJWT is used to request a JWT for accessing the API gateway
	APIGatewayAccessJWT JWTType = "api"
)

// JWTOption is a function that sets an option on the jwtOptions struct.
type JWTOption func(*jwtOptions)

// jwtOptions holds the options for the GetJWT functions.
type jwtOptions struct {
	JWTType              JWTType
	WorkspaceGroupID     string
	ExternalServerURL    string
	GCPAudience          string
	AssumeRoleIdentifier string // Role ARN (AWS), service account email (GCP), or managed identity ID (Azure)
}

// WithExternalServerURL sets the external server URL option.
func WithExternalServerURL(externalServerURL string) JWTOption {
	return func(o *jwtOptions) {
		o.ExternalServerURL = externalServerURL
	}
}

// WithGCPAudience sets the GCP audience for identity token requests.
func WithGCPAudience(audience string) JWTOption {
	return func(o *jwtOptions) {
		o.GCPAudience = audience
	}
}

// WithAssumeRole sets the role ARN (AWS), service account email (GCP),
// or managed identity ID (Azure) to assume before requesting the JWT.
func WithAssumeRole(roleIdentifier string) JWTOption {
	return func(o *jwtOptions) {
		o.AssumeRoleIdentifier = roleIdentifier
	}
}

// getIdentityHeaders determines the cloud provider and calls the provider-specific
// function to get the identity headers.
func getIdentityHeaders(ctx context.Context, gcpAudience string, assumeRoleIdentifier string) (map[string]string, string, error) {
	// Detect the cloud environment. We check the environment variables
	// that are set by the cloud providers.
	if os.Getenv("AWS_EXECUTION_ENV") != "" {
		return getAWSIdentityHeaders(ctx, assumeRoleIdentifier)
	}
	if os.Getenv("GCE_METADATA_HOST") != "" {
		return getGCPIdentityHeaders(ctx, gcpAudience, assumeRoleIdentifier)
	}
	if os.Getenv("AZURE_ENV") != "" {
		return getAzureIdentityHeaders(ctx, assumeRoleIdentifier)
	}
	return nil, "", errors.New("cloud provider not detected")
}

// getJWT retrieves a JWT from the external server using the cloud provider's identity.
// It is called by GetDatabaseJWT and GetAPIJWT.
func getJWT(ctx context.Context, options jwtOptions) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if options.ExternalServerURL == "" {
		return "", errors.New("external server URL is required")
	}

	if options.GCPAudience == "" {
		options.GCPAudience = gcpDefaultAudience
	}

	identityHeaders, cloudProvider, err := getIdentityHeaders(ctx, options.GCPAudience, options.AssumeRoleIdentifier)
	if err != nil {
		return "", fmt.Errorf("failed to get identity headers: %w", err)
	}

	// Construct the URL.
	targetURL := options.ExternalServerURL // Start with the base URL
	targetURL = strings.ReplaceAll(targetURL, ":cloudProvider", cloudProvider)
	targetURL = strings.ReplaceAll(targetURL, ":jwtType", string(options.JWTType))

	uri, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("invalid external server URL: %w", err)
	}

	// Add optional query parameters. These are application-specific and
	// provide more context to the external server.
	q := uri.Query()

	if options.JWTType == DatabaseAccessJWT {
		q.Add("workspaceGroupID", options.WorkspaceGroupID)
	}
	uri.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), nil)
	if err != nil {
		return "", fmt.Errorf("error creating request to external server: %w", err)
	}

	// Add identity headers. These headers prove our identity to the
	// external server.
	for key, value := range identityHeaders {
		req.Header.Set(key, value)
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second, // Increased timeout for the HTTP request.
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error calling external server: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("external server returned non-OK status: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var response struct {
		JWT string `json:"jwt"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return "", fmt.Errorf("cannot parse response: %w", err)
	}

	if response.JWT == "" {
		return "", errors.New("received empty JWT from server")
	}

	return response.JWT, nil
}

// GetDatabaseJWT retrieves a database JWT from the external server using the cloud provider's identity.
//
// The workspaceGroupID parameter is required for database JWTs. The options are passed as a
// variable number of JWTOption functions.
func GetDatabaseJWT(ctx context.Context, workspaceGroupID string, opts ...JWTOption) (string, error) {
	// Start with the default options.
	options := jwtOptions{
		JWTType:           DatabaseAccessJWT,
		WorkspaceGroupID:  workspaceGroupID,
		ExternalServerURL: defaultServer,
	}

	// Apply the caller-provided options.
	for _, opt := range opts {
		opt(&options)
	}

	if options.WorkspaceGroupID == "" {
		return "", errors.New("workspaceGroupID is required for database JWT type")
	}

	return getJWT(ctx, options)
}

// GetAPIJWT retrieves an API JWT from the external server using the cloud provider's identity.
//
// The options are passed as a variable number of JWTOption functions.
func GetAPIJWT(ctx context.Context, opts ...JWTOption) (string, error) {
	// Start with the default options.
	options := jwtOptions{
		JWTType:           APIGatewayAccessJWT,
		ExternalServerURL: defaultServer,
	}

	// Apply the caller-provided options.
	for _, opt := range opts {
		opt(&options)
	}

	return getJWT(ctx, options)
}

// getAWSIdentityHeaders gets the identity headers for AWS.
// If a role ARN is provided, it will first assume that role.
func getAWSIdentityHeaders(ctx context.Context, roleARN string) (map[string]string, string, error) {
	// Use the AWS SDK to get the identity.
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)

	// If roleARN is provided, assume that role first
	if roleARN != "" {
		// Generate a unique session name
		sessionName := fmt.Sprintf("SingleStoreAuth-%d", time.Now().Unix())

		// Assume the specified role
		assumeRoleInput := &sts.AssumeRoleInput{
			RoleArn:         &roleARN,
			RoleSessionName: &sessionName,
			DurationSeconds: aws.Int32(3600), // 1 hour
		}

		assumeRoleOutput, err := stsClient.AssumeRole(ctx, assumeRoleInput)
		if err != nil {
			return nil, "", fmt.Errorf("failed to assume role %s: %w", roleARN, err)
		}

		// Use the temporary credentials from assumed role
		headers := map[string]string{
			"X-AWS-Access-Key-ID":     *assumeRoleOutput.Credentials.AccessKeyId,
			"X-AWS-Secret-Access-Key": *assumeRoleOutput.Credentials.SecretAccessKey,
			"X-AWS-Session-Token":     *assumeRoleOutput.Credentials.SessionToken,
		}
		return headers, "aws", nil
	}

	// Original implementation for when no role is assumed
	input := &sts.GetSessionTokenInput{}
	output, err := stsClient.GetSessionToken(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get session token: %w", err)
	}

	headers := map[string]string{
		"X-AWS-Access-Key-ID":     *output.Credentials.AccessKeyId,
		"X-AWS-Secret-Access-Key": *output.Credentials.SecretAccessKey,
		"X-AWS-Session-Token":     *output.Credentials.SessionToken,
	}
	return headers, "aws", nil
}

// getGCPIdentityHeaders gets the identity headers for GCP.
// If a service account email is provided, it will impersonate that service account.
func getGCPIdentityHeaders(ctx context.Context, audience string, serviceAccountEmail string) (map[string]string, string, error) {
	// If serviceAccountEmail is provided, get token through impersonation
	if serviceAccountEmail != "" {
		// First get our own identity token for authentication
		selfToken, err := getGCPIDToken(ctx, "https://iamcredentials.googleapis.com/")
		if err != nil {
			return nil, "", fmt.Errorf("failed to get self identity token: %w", err)
		}

		// Use IAM API to impersonate the service account
		impersonationURL := fmt.Sprintf(
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken",
			serviceAccountEmail,
		)

		requestBody := fmt.Sprintf(`{"audience":"%s"}`, audience)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, impersonationURL, strings.NewReader(requestBody))
		if err != nil {
			return nil, "", err
		}

		// Use our self token to authenticate the impersonation request
		req.Header.Set("Authorization", "Bearer "+selfToken)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("failed to impersonate service account: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return nil, "", fmt.Errorf("impersonation failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var tokenResponse struct {
			Token string `json:"token"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
			return nil, "", fmt.Errorf("failed to parse impersonation response: %w", err)
		}

		if tokenResponse.Token == "" {
			return nil, "", errors.New("received empty token from impersonation service")
		}

		headers := map[string]string{
			"Authorization": "Bearer " + tokenResponse.Token,
		}
		return headers, "gcp", nil
	}

	// Original implementation when no service account impersonation is needed
	idToken, err := getGCPIDToken(ctx, audience)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get GCP ID token: %w", err)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + idToken,
	}
	return headers, "gcp", nil
}

// getAzureIdentityHeaders gets the identity headers for Azure.
// If a managed identity ID is provided, it will use that identity.
func getAzureIdentityHeaders(ctx context.Context, managedIdentityID string) (map[string]string, string, error) {
	url := fmt.Sprintf("%s?api-version=%s&resource=%s", azureMetadataURL, azureAPIVersion, azureResourceServer)

	// If a specific managed identity ID is provided, add it to the request
	if managedIdentityID != "" {
		url = fmt.Sprintf("%s&client_id=%s", url, managedIdentityID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}

	// Azure requires this header for managed identity requests
	req.Header.Set("Metadata", "true")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get Azure Managed Identity token: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read Azure token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("Azure token request failed: %d, %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		return nil, "", fmt.Errorf("failed to parse Azure token response: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		return nil, "", errors.New("received empty access token from Azure")
	}

	headers := map[string]string{
		"Authorization": "Bearer " + tokenResponse.AccessToken,
	}
	return headers, "azure", nil
}

// getMetadata retrieves data from a given URL with a timeout. This is used
// by the cloud provider specific functions to get metadata.
func getMetadata(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	client := &http.Client{
		Timeout: 5 * time.Second, // Keep the timeout short.
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to retrieve metadata from %s, status code: %d, body: %s", url, resp.StatusCode, string(bodyBytes))
	}

	return string(bodyBytes), nil
}

// getAWSMetadata retrieves specific AWS metadata.
func getAWSMetadata(ctx context.Context, key string) (string, error) {
	url := awsMetadataURL + key
	return getMetadata(ctx, url)
}

// getGCPIDToken retrieves the GCP ID token.
func getGCPIDToken(ctx context.Context, audience string) (string, error) {
	tokenURL := fmt.Sprintf("%sinstance/service-accounts/default/identity?audience=%s", gcpMetadataURL, audience)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google") // Correct header for GCP metadata service

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
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
