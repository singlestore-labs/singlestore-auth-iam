package s2iam

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/memsql/errors"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/aws"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

const (
	// defaultServer is the default authentication server endpoint
	defaultServer = "https://authsvc.singlestore.com/auth/iam/:jwtType"

	// ServerURLEnv overrides the authentication server URL when WithServerURL is not
	// given. The Python and Java clients honor the same variable, so one setting
	// configures a mixed-language fleet. The value may use the :cloudProvider and
	// :jwtType placeholders and must be https:// unless WithAllowHTTP is set.
	ServerURLEnv = "S2IAM_SERVER_URL"

	// defaultHTTPClientTimeout is used for outbound auth server requests
	defaultHTTPClientTimeout = 10 * time.Second
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
	JWTType                     JWTType
	WorkspaceGroupID            string
	ServerURL                   string
	AllowHTTP                   bool
	Provider                    models.CloudProviderClient
	AdditionalParams            map[string]string
	AssumeRoleIdentifier        string
	AssumeRoleSessionName       string
	IdentityFormatPreference    []string
	identityFormatPreferenceSet bool
}

// WithServerURL sets the authentication server URL. It takes precedence over the
// ServerURLEnv environment variable and the built-in default.
func WithServerURL(serverURL string) JWTOption {
	return jwtOption(func(o *jwtOptions) {
		o.ServerURL = serverURL
	})
}

// serverURL resolves the effective authentication server URL using the precedence
// option > env var > built-in default.
func (o jwtOptions) serverURL() string {
	if o.ServerURL != "" {
		return o.ServerURL
	}
	if env := os.Getenv(ServerURLEnv); env != "" {
		return env
	}
	return defaultServer
}

// WithAllowHTTP permits http:// authentication server URLs. Intended for local testing only.
func WithAllowHTTP() JWTOption {
	return jwtOption(func(o *jwtOptions) {
		o.AllowHTTP = true
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

// WithAssumeRoleSessionName sets the AWS STS RoleSessionName used on the
// AssumeRole call this library performs for WithAssumeRole. It applies only to
// that library-driven AssumeRole path, not to ambient credentials (EC2 instance
// profiles, EKS IRSA), whose session names are assigned by AWS/the infrastructure.
//
// The session name becomes part of the identity under the "aws-arn" format,
// whose JWT sub is the full STS ARN arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION.
// When unset, the library uses a stable default (DefaultRoleSessionName), so the
// full ARN is deterministic and can be pre-configured as a cloud principal /
// database user. Set a stable value here if you need a different one. It does not
// affect the "aws-iam-role-arn" format (the session-stripped base role ARN), which
// is the default as of v0.6.0, so this option only matters when you request
// "aws-arn" via WithIdentityFormatPreference.
func WithAssumeRoleSessionName(sessionName string) JWTOption {
	return jwtOption(func(o *jwtOptions) {
		o.AssumeRoleSessionName = sessionName
	})
}

// WithIdentityFormatPreference sets the ordered identity-format preference list
// sent to the auth service via the X-S2IAM-Identity-Format-Preference header. The
// verifier chooses the first format that is both server-supported and valid for
// the attested identity (for example prefer "aws-iam-role-arn" and fall back to
// "aws-arn"). Tokens are provider-prefixed, so a single list can serve a
// heterogeneous fleet; unknown or inapplicable tokens are ignored.
//
// Precedence: this explicit option > the S2IAM_IDENTITY_FORMAT_PREFERENCE
// environment variable > DefaultIdentityFormatPreference. A preference that omits a
// provider gives that provider's identity back to the verifier's ordering.
func WithIdentityFormatPreference(formats ...string) JWTOption {
	return jwtOption(func(o *jwtOptions) {
		o.IdentityFormatPreference = formats
		o.identityFormatPreferenceSet = true
	})
}

// defaultIdentityFormatPreference names every provider, each run ending at that
// provider's always-valid floor, so the issued identity is pinned by the client
// rather than left to the verifier's configured default ordering.
//
// AWS leads with the session-stripped base IAM role ARN. GCP and Azure reproduce the
// verifier's own ordering, so naming them pins the identity without changing it.
// Formats a preceding floor already makes unreachable (aws-role-id,
// azure-resource-id) are omitted: they are opt-in only.
var defaultIdentityFormatPreference = []string{
	string(models.FormatAWSIAMRoleARN), string(models.FormatAWSARN),
	string(models.FormatGCPSAEmail), string(models.FormatGCPSAUniqueID),
	string(models.FormatAzureObjectID),
}

// DefaultIdentityFormatPreference returns a copy of the built-in preference, for
// callers that report it (the CLI's help text) or extend it.
func DefaultIdentityFormatPreference() []string {
	return slices.Clone(defaultIdentityFormatPreference)
}

// identityFormatPreference resolves the effective preference list using the
// precedence option > env var > built-in default.
func (o jwtOptions) identityFormatPreference() []string {
	if o.identityFormatPreferenceSet {
		return o.IdentityFormatPreference
	}
	if env := os.Getenv(models.IdentityFormatPreferenceEnv); env != "" {
		formats := models.ParseIdentityFormatPreference(env)
		out := make([]string, len(formats))
		for i, f := range formats {
			out[i] = string(f)
		}
		return out
	}
	return defaultIdentityFormatPreference
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

	serverURL := jwtOpts.serverURL()

	probeURL := strings.ReplaceAll(strings.ReplaceAll(serverURL, ":cloudProvider", "aws"), ":jwtType", string(jwtOpts.JWTType))
	if _, err := validateAuthServerURL(probeURL, jwtOpts.AllowHTTP); err != nil {
		return "", err
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

	if jwtOpts.AssumeRoleSessionName != "" {
		jwtOpts.AdditionalParams[aws.RoleSessionNameParam] = jwtOpts.AssumeRoleSessionName
	}

	identityHeaders, identity, err := provider.GetIdentityHeaders(ctx, jwtOpts.AdditionalParams)
	if err != nil {
		return "", errors.Errorf("failed to get identity headers: %w", err)
	}

	// Construct the URL
	targetURL := serverURL
	targetURL = strings.ReplaceAll(targetURL, ":cloudProvider", string(identity.Provider))
	targetURL = strings.ReplaceAll(targetURL, ":jwtType", string(jwtOpts.JWTType))

	uri, err := validateAuthServerURL(targetURL, jwtOpts.AllowHTTP)
	if err != nil {
		return "", err
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

	// Advertise the client's identity-format preference (content negotiation). The
	// verifier chooses the first supported-and-valid format; older servers ignore
	// this header and keep their default behavior.
	if pref := jwtOpts.identityFormatPreference(); len(pref) > 0 {
		req.Header.Set(models.IdentityFormatPreferenceHeader, strings.Join(pref, ","))
	}

	// Send request
	httpClient := &http.Client{Timeout: defaultHTTPClientTimeout}
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
	}, opts)
}

// GetAPIJWT retrieves an API JWT from the authentication server
func GetAPIJWT(ctx context.Context, opts ...JWTOption) (string, error) {
	return getJWT(ctx, jwtOptions{
		JWTType: APIGatewayAccessJWT,
	}, opts)
}
