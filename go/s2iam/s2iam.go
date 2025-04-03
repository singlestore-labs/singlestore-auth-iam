package s2iam

// Initial version of this library written by Gemini
// https://g.co/gemini/share/6af3a6377907

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

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const defaultServer = "https://auth.singlestore.com/auth/iam"

// JWTType represents the type of JWT requested.  This is used to tell
// the external authentication service what kind of JWT we want.
type JWTType string

const (
	// DatabaseAccessJWT is used to request a JWT for accessing the
	databaseAccessJWT JWTType = "database"

	// ApiGatewayAccessJWT is used to request a JWT for accessing
	apiGatewayAccessJWT JWTType = "api"
)

// JWTOption is a function that sets an option on the jwtOptions struct.
type JWTOption func(*jwtOptions)

// jwtOptions holds the options for the GetJWT functions. It's no longer
// exported, as it's only used internally.
type jwtOptions struct {
	JWTType          JWTType
	WorkspaceGroupID string
	ExternalServerURL string
}

// WithExternalServerURL sets the external server URL option.
func WithExternalServerURL(externalServerURL string) JWTOption {
	return func(o *jwtOptions) {
		o.ExternalServerURL = externalServerURL
	}
}

// getIdentityHeaders determines the cloud provider and calls the provider-specific
// function to get the identity headers.
func getIdentityHeaders(ctx context.Context) (map[string]string, string, error) {
	// Detect the cloud environment.  We check the environment variables
	// that are set by the cloud providers.
	if os.Getenv("AWS_EXECUTION_ENV") != "" {
		return getAWSIdentityHeaders(ctx)
	}
	if os.Getenv("GCE_METADATA_HOST") != "" {
		return getGCPIdentityHeaders(ctx)
	}
	if os.Getenv("AZURE_ENV") != "" {
		return getAzureIdentityHeaders(ctx)
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

	identityHeaders, cloudProvider, err := getIdentityHeaders(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get identity headers: %w", err)
	}

	// Construct the URL.
	var targetURL string
	targetURL = options.ExternalServerURL // Start with the base URL
	targetURL = strings.ReplaceAll(targetURL, ":cloudProvider", cloudProvider)
	targetURL = strings.ReplaceAll(targetURL, ":jwtType", string(options.JWTType))

	uri, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("invalid external server URL: %w", err)
	}

	// Add optional query parameters.  These are application-specific and
	// provide more context to the external server.
	q := uri.Query()

	if options.JWTType == databaseAccessJWT {
		q.Add("workspaceGroupID", options.WorkspaceGroupID)
	}
	uri.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri.String(), nil)
	if err != nil {
		return "", fmt.Errorf("error creating request to external server: %w", err)
	}

	// Add identity headers.  These headers prove our identity to the
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

	if resp.StatusCode != http.StatusOK {
		// Read the response body to include in the error message.
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", fmt.Errorf("external server returned non-OK status: %d, and error reading response body: %w", resp.StatusCode, readErr)
		}
		return "", fmt.Errorf("external server returned non-OK status: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Read the entire response body.  We do this *before* checking for a
	// JSON structure, in case the server returns plain text.
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	var response struct {
		JWT string `json:"jwt"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return "", fmt.Errorf("cannot parse response: %w", err)
	}

	return response.JWT, nil
}

// GetDatabaseJWT retrieves a database JWT from the external server using the cloud provider's identity.
//
// The workspaceGroupID parameter is required for database JWTs.  The options are passed as a
// variable number of JWTOption functions.
func GetDatabaseJWT(ctx context.Context, workspaceGroupID string, opts ...JWTOption) (string, error) {
	// Start with the default options.
	options := jwtOptions{
		JWTType:          databaseAccessJWT,
		WorkspaceGroupID: workspaceGroupID,
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
		JWTType:          apiGatewayAccessJWT,
		ExternalServerURL: defaultServer,
	}

	// Apply the caller-provided options.
	for _, opt := range opts {
		opt(&options)
	}

	return getJWT(ctx, options)
}

// getAWSIdentityHeaders gets the identity headers for AWS.
func getAWSIdentityHeaders(ctx context.Context) (map[string]string, string, error) {
	// Use the AWS SDK to get the identity.  We use GetSessionToken,
	// which does not require any special permissions.  This is the
	// most secure way to get an identity.
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)
	input := &sts.GetSessionTokenInput{} // No input needed for GetSessionToken
	output, err := stsClient.GetSessionToken(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get session token: %w", err)
	}

	// The output contains the access key, secret access key, and session
	// token.  These are used to sign requests to AWS.  The server can
	// then use these to verify the identity of the caller.  We do NOT
	// include the ARN.
	headers := map[string]string{
		"X-AWS-Access-Key-ID":     *output.Credentials.AccessKeyId,
		"X-AWS-Secret-Access-Key": *output.Credentials.SecretAccessKey,
		"X-AWS-Session-Token":     *output.Credentials.SessionToken,
	}
	return headers, "aws", nil
}

// getGCPIdentityHeaders gets the identity headers for GCP.
func getGCPIdentityHeaders(ctx context.Context) (map[string]string, string, error) {
	idToken, err := getGCPMetadata(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get GCP ID token: %w", err)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + idToken,
	}
	return headers, "gcp", nil
}

// getAzureIdentityHeaders gets the identity headers for Azure.
func getAzureIdentityHeaders(ctx context.Context) (map[string]string, string, error) {
	url := fmt.Sprintf("%s?api-version=%s&resource=%s", azureMetadataURL, azureAPIVersion, azureResourceServer)
	responseJSON, err := getAzureMetadata(ctx, url)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get Azure Managed Identity token: %w", err)
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(responseJSON), &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to parse Azure token response: %w", err)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + tokenResponse.AccessToken,
	}
	return headers, "azure", nil
}

// getMetadata retrieves data from a given URL with a timeout.  This is used
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

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body) // Read error for better message.
		return "", fmt.Errorf("failed to retrieve metadata from %s, status code: %d, body: %s", url, resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}

// The following functions exist to provide a consistent API for fetching
// metadata from each of the cloud providers.
const (
	awsMetadataURL   = "http://169.254.169.254/latest/meta-data/"
	gcpMetadataURL   = "http://metadata.google.internal/computeMetadata/v1/"
	azureMetadataURL = "http://169.254.169.254/metadata/identity/oauth2/token"
	gcpAudience      = "your-external-auth-server" //  Configurable.
)

// getAWSMetadata retrieves specific AWS metadata.
func getAWSMetadata(ctx context.Context, key string) (string, error) {
	url := awsMetadataURL + key
	return getMetadata(ctx, url)
}

// getGCPMetadata retrieves the GCP ID token.
func getGCPMetadata(ctx context.Context) (string, error) {
	tokenURL := fmt.Sprintf("%sinstance/service-accounts/default/identity?audience=%s", gcpMetadataURL, gcpAudience)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata", "true")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GCP metadata request failed: %s, body: %s", tokenURL, string(bodyBytes))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// getAzureMetadata retrieves Azure Managed Identity access token.
func getAzureMetadata(ctx context.Context, url string) (string, error) {
	return getMetadata(ctx, url)
}

// getCloudProvider determines the cloud provider.
func getCloudProvider() (string, error) {
	if os.Getenv("AWS_EXECUTION_ENV") != "" {
		return "aws", nil
	}
	if os.Getenv("GCE_METADATA_HOST") != "" {
		return "gcp", nil
	}
	if os.Getenv("AZURE_ENV") != "" {
		return "azure", nil
	}
	return "", errors.New("cloud provider not detected")
}

