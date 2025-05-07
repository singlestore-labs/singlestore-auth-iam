package s2iam

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/memsql/errors"
)

// AWSClient implements the CloudProviderClient interface for AWS
type AWSClient struct {
	stsClient *sts.Client
	roleARN   string
	identity  *CloudIdentity
	detected  bool
	region    string     // AWS region to use for API calls
	mu        sync.Mutex // Added for concurrency safety
}

// awsClient is a singleton instance of AWSClient
var awsClient = &AWSClient{}

// NewAWSClient returns the AWS client singleton
func NewAWSClient() CloudProviderClient {
	return awsClient
}

// ensureRegion determines and sets the AWS region for API calls
func (c *AWSClient) ensureRegion(ctx context.Context) error {
	if c.region != "" {
		return nil
	}

	if debugging {
		fmt.Println("AWS ensureRegion - Determining region")
	}

	// Try environment variables first (fastest method)
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}

	// Try to get region from metadata service
	if region == "" {
		if debugging {
			fmt.Println("AWS ensureRegion - Trying metadata service for region")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"http://169.254.169.254/latest/meta-data/placement/region", nil)
		if err == nil {
			client := &http.Client{}
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					body, err := io.ReadAll(resp.Body)
					if err == nil && len(body) > 0 {
						region = string(body)
						if debugging {
							fmt.Printf("AWS ensureRegion - Got region from metadata: %s\n", region)
						}
					}
				}
			}
		}
	}

	// Try SDK config if needed
	if region == "" {
		if debugging {
			fmt.Println("AWS ensureRegion - Trying SDK default config for region")
		}
		cfg, err := config.LoadDefaultConfig(ctx)
		if err == nil && cfg.Region != "" {
			region = cfg.Region
			if debugging {
				fmt.Printf("AWS ensureRegion - Got region from SDK config: %s\n", region)
			}
		}
	}

	// Default to us-east-1 if all else fails
	if region == "" {
		region = "us-east-1"
		if debugging {
			fmt.Println("AWS ensureRegion - Using default region: us-east-1")
		}
	}

	c.region = region
	return nil
}

// Detect tests if we are executing within AWS.
func (c *AWSClient) Detect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if detection was already performed successfully
	if c.detected {
		return nil
	}

	if debugging {
		fmt.Println("AWS Detection - Starting detection")
	}

	// Check common AWS environment variables (fast check first)
	if os.Getenv("AWS_EXECUTION_ENV") != "" || os.Getenv("AWS_REGION") != "" ||
		os.Getenv("AWS_DEFAULT_REGION") != "" || os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		if debugging {
			fmt.Println("AWS Detection - Found AWS environment variables")
		}
		c.detected = true // Mark detected first to avoid re-detection

		// Initialize region first (separate from full initialization)
		if err := c.ensureRegion(ctx); err != nil {
			c.detected = false // Reset detection on failure
			return err
		}

		// Return success - the STS client will be created lazily when needed
		return nil
	}

	// Try to access the AWS instance metadata service
	// Try IMDSv2 first (token-based method)
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPut,
		"http://169.254.169.254/latest/api/token", nil)
	if err == nil {
		tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
		client := &http.Client{}
		resp, err := client.Do(tokenReq)

		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if debugging {
					fmt.Println("AWS Detection - Metadata service detected")
				}
				c.detected = true // Mark detected first to avoid re-detection

				// Initialize region first (separate from full initialization)
				if err := c.ensureRegion(ctx); err != nil {
					c.detected = false // Reset detection on failure
					return err
				}

				// Return success - the STS client will be created lazily when needed
				return nil
			}
			if debugging {
				fmt.Printf("AWS Detection - IMDSv2 token request failed with status: %d\n", resp.StatusCode)
			}
		} else {
			if debugging {
				fmt.Printf("AWS Detection - IMDSv2 token request failed: %v\n", err)
			}
		}
	}

	// Fall back to direct metadata check
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		return errors.Errorf("not running on AWS: %w", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if debugging {
				fmt.Println("AWS Detection - Direct metadata service detected")
			}
			c.detected = true // Mark detected first to avoid re-detection

			// Initialize region first (separate from full initialization)
			if err := c.ensureRegion(ctx); err != nil {
				c.detected = false // Reset detection on failure
				return err
			}

			// Return success - the STS client will be created lazily when needed
			return nil
		}
		if debugging {
			fmt.Printf("AWS Detection - Direct metadata check failed with status: %d\n", resp.StatusCode)
		}
	} else {
		if debugging {
			fmt.Printf("AWS Detection - Direct metadata check failed: %v\n", err)
		}
	}

	return errors.New("not running on AWS: failed to access instance metadata service")
}

// initialize sets up the AWS SDK client
func (c *AWSClient) initialize(ctx context.Context) error {
	if debugging {
		fmt.Println("AWS Initialize - Starting initialization")
	}

	if err := c.ensureRegion(ctx); err != nil {
		return err
	}

	if debugging {
		fmt.Printf("AWS Initialize - Using region: %s\n", c.region)
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(c.region))
	if err != nil {
		return errors.Errorf("failed to load AWS config: %w", err)
	}

	c.stsClient = sts.NewFromConfig(cfg)
	if debugging {
		fmt.Println("AWS Initialize - Successfully created STS client")
	}
	return nil
}

// GetType returns the cloud provider type
func (c *AWSClient) GetType() CloudProviderType {
	return ProviderAWS
}

// WithRegion returns a new client configured to use the specified AWS region
func (c *AWSClient) WithRegion(region string) CloudProviderClient {
	newClient := &AWSClient{
		stsClient: c.stsClient,
		identity:  c.identity,
		detected:  c.detected,
		roleARN:   c.roleARN,
		region:    region,
	}
	return newClient
}

// GetIdentityHeaders returns the headers needed to authenticate with the SingleStore auth service
func (c *AWSClient) GetIdentityHeaders(ctx context.Context, additionalParams map[string]string) (map[string]string, *CloudIdentity, error) {
	c.mu.Lock()
	detected := c.detected
	roleARN := c.roleARN
	c.mu.Unlock()

	if !detected {
		return nil, nil, ErrProviderNotDetected
	}

	// Initialize STS client if needed
	c.mu.Lock()
	if c.stsClient == nil {
		if debugging {
			fmt.Println("AWS GetIdentityHeaders - Initializing STS client")
		}

		if err := c.initialize(ctx); err != nil {
			c.mu.Unlock()
			return nil, nil, errors.Errorf("failed to initialize AWS client: %w", err)
		}
	}
	c.mu.Unlock()

	// If roleARN is provided, assume that role first
	if roleARN != "" {
		if debugging {
			fmt.Printf("AWS GetIdentityHeaders - Assuming role: %s\n", roleARN)
		}
		// Generate a unique session name
		sessionName := fmt.Sprintf("SingleStoreAuth-%d", time.Now().Unix())

		// Assume the specified role
		assumeRoleInput := &sts.AssumeRoleInput{
			RoleArn:         &roleARN,
			RoleSessionName: &sessionName,
			DurationSeconds: aws.Int32(3600), // 1 hour
		}

		assumeRoleOutput, err := c.stsClient.AssumeRole(ctx, assumeRoleInput)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to assume role %s: %w", roleARN, err)
		}

		// Use the temporary credentials from assumed role
		headers := map[string]string{
			"X-AWS-Access-Key-ID":     *assumeRoleOutput.Credentials.AccessKeyId,
			"X-AWS-Secret-Access-Key": *assumeRoleOutput.Credentials.SecretAccessKey,
			"X-AWS-Session-Token":     *assumeRoleOutput.Credentials.SessionToken,
		}

		// Get caller identity to populate the CloudIdentity object
		tempCfg, err := config.LoadDefaultConfig(ctx,
			config.WithRegion(c.region),
			config.WithCredentialsProvider(aws.CredentialsProviderFunc(
				func(ctx context.Context) (aws.Credentials, error) {
					return aws.Credentials{
						AccessKeyID:     *assumeRoleOutput.Credentials.AccessKeyId,
						SecretAccessKey: *assumeRoleOutput.Credentials.SecretAccessKey,
						SessionToken:    *assumeRoleOutput.Credentials.SessionToken,
					}, nil
				},
			)),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load AWS config with assumed role: %w", err)
		}

		tempSTS := sts.NewFromConfig(tempCfg)
		identity, err := c.getIdentityFromSTS(ctx, tempSTS)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get identity after assuming role: %w", err)
		}

		return headers, identity, nil
	}

	// First try to get the caller identity to check if we're already using session credentials
	if debugging {
		fmt.Println("AWS GetIdentityHeaders - Getting caller identity")
	}
	callerIdentity, err := c.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get caller identity: %w", err)
	}

	// Check if we're already using session credentials
	// One way to tell is by checking if the ARN contains ":assumed-role/" or if the session token exists in the environment
	isUsingSessionCredentials := strings.Contains(*callerIdentity.Arn, ":assumed-role/") ||
		os.Getenv("AWS_SESSION_TOKEN") != ""

	// If we're using session credentials, we can't call GetSessionToken
	// So we'll use the credentials we already have
	if isUsingSessionCredentials {
		if debugging {
			fmt.Println("AWS GetIdentityHeaders - Using existing session credentials")
		}

		// Get the current credentials from the SDK
		creds, err := c.stsClient.Options().Credentials.Retrieve(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve credentials: %w", err)
		}

		// Use the current credentials
		headers := map[string]string{
			"X-AWS-Access-Key-ID":     creds.AccessKeyID,
			"X-AWS-Secret-Access-Key": creds.SecretAccessKey,
		}

		// Add session token if it exists
		if creds.SessionToken != "" {
			headers["X-AWS-Session-Token"] = creds.SessionToken
		}

		// Create identity from the caller identity we already obtained
		identity, err := c.parseIdentityFromCallerIdentity(callerIdentity)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse identity: %w", err)
		}

		return headers, identity, nil
	}

	// We're using permanent credentials, so we can call GetSessionToken
	if debugging {
		fmt.Println("AWS GetIdentityHeaders - Getting session token")
	}
	input := &sts.GetSessionTokenInput{}
	output, err := c.stsClient.GetSessionToken(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get session token: %w", err)
	}

	headers := map[string]string{
		"X-AWS-Access-Key-ID":     *output.Credentials.AccessKeyId,
		"X-AWS-Secret-Access-Key": *output.Credentials.SecretAccessKey,
		"X-AWS-Session-Token":     *output.Credentials.SessionToken,
	}

	identity, err := c.getIdentityFromSTS(ctx, c.stsClient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get identity: %w", err)
	}

	return headers, identity, nil
}

// parseIdentityFromCallerIdentity converts a GetCallerIdentityOutput to a CloudIdentity
func (c *AWSClient) parseIdentityFromCallerIdentity(callerIdentity *sts.GetCallerIdentityOutput) (*CloudIdentity, error) {
	// Parse the ARN to extract region and resource type
	arnParts := strings.Split(*callerIdentity.Arn, ":")
	var region, resourceType string

	if len(arnParts) >= 4 {
		region = arnParts[3]
	}

	if len(arnParts) >= 6 {
		resourceParts := strings.Split(arnParts[5], "/")
		if len(resourceParts) >= 2 {
			resourceType = resourceParts[0]
		}
	}

	return &CloudIdentity{
		Provider:     ProviderAWS,
		Identifier:   *callerIdentity.Arn,
		AccountID:    *callerIdentity.Account,
		Region:       region,
		ResourceType: resourceType,
		AdditionalClaims: map[string]string{
			"UserId": *callerIdentity.UserId,
		},
	}, nil
}

// getIdentityFromSTS calls GetCallerIdentity and populates a CloudIdentity object
func (c *AWSClient) getIdentityFromSTS(ctx context.Context, stsClient *sts.Client) (*CloudIdentity, error) {
	callerIdentity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %w", err)
	}

	// Parse the ARN to extract region and resource type
	arnParts := strings.Split(*callerIdentity.Arn, ":")
	var region, resourceType string

	if len(arnParts) >= 4 {
		region = arnParts[3]
	}

	if len(arnParts) >= 6 {
		resourceParts := strings.Split(arnParts[5], "/")
		if len(resourceParts) >= 2 {
			resourceType = resourceParts[0]
		}
	}

	return &CloudIdentity{
		Provider:     ProviderAWS,
		Identifier:   *callerIdentity.Arn,
		AccountID:    *callerIdentity.Account,
		Region:       region,
		ResourceType: resourceType,
		AdditionalClaims: map[string]string{
			"UserId": *callerIdentity.UserId,
		},
	}, nil
}

// AssumeRole configures the provider to use an alternate identity
func (c *AWSClient) AssumeRole(roleIdentifier string) CloudProviderClient {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create a new client to avoid modifying the original
	newClient := &AWSClient{
		stsClient: c.stsClient,
		identity:  c.identity,
		detected:  c.detected,
		roleARN:   roleIdentifier,
		region:    c.region,
	}

	return newClient
}

// AWSVerifier implements the CloudProviderVerifier interface for AWS
type AWSVerifier struct {
	logLevel int
	logger   Logger
	mu       sync.RWMutex
}

// awsVerifier is a singleton instance for AWSVerifier
var awsVerifier = &AWSVerifier{}

// NewAWSVerifier creates or configures the AWS verifier
func NewAWSVerifier(logger Logger, logLevel int) CloudProviderVerifier {
	awsVerifier.mu.Lock()
	defer awsVerifier.mu.Unlock()

	if logger != nil {
		awsVerifier.logger = logger
		awsVerifier.logLevel = logLevel
	}
	return awsVerifier
}

// HasHeaders returns true if the request has AWS authentication headers
func (v *AWSVerifier) HasHeaders(r *http.Request) bool {
	return r.Header.Get("X-AWS-Access-Key-ID") != "" &&
		r.Header.Get("X-AWS-Secret-Access-Key") != "" &&
		r.Header.Get("X-AWS-Session-Token") != ""
}

// VerifyRequest validates the AWS credentials and returns the identity
func (v *AWSVerifier) VerifyRequest(ctx context.Context, r *http.Request) (*CloudIdentity, error) {
	v.mu.RLock()
	logger := v.logger
	logLevel := v.logLevel
	v.mu.RUnlock()

	accessKeyID := r.Header.Get("X-AWS-Access-Key-ID")
	secretAccessKey := r.Header.Get("X-AWS-Secret-Access-Key")
	sessionToken := r.Header.Get("X-AWS-Session-Token")

	if accessKeyID == "" || secretAccessKey == "" || sessionToken == "" {
		if logger != nil && logLevel > 0 {
			logger.Logf("Missing required AWS authentication headers")
		}
		return nil, errors.New("missing required AWS authentication headers")
	}

	if logger != nil && logLevel > 1 {
		logger.Logf("Creating AWS config with provided credentials")
	}

	// Create a region-independent configuration first
	// This allows STS global endpoint to be used which doesn't require region
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithCredentialsProvider(aws.CredentialsProviderFunc(
			func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     accessKeyID,
					SecretAccessKey: secretAccessKey,
					SessionToken:    sessionToken,
				}, nil
			},
		)),
	)
	if err != nil {
		if logger != nil && logLevel > 0 {
			logger.Logf("Failed to load AWS config: %v", err)
		}
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Use us-east-1 as the default region for STS if no region is set
	// STS is a global service but requires a region in the config
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
		if logger != nil && logLevel > 1 {
			logger.Logf("No region specified, using us-east-1 for STS")
		}
	}

	// Create an STS client with the configuration
	stsClient := sts.NewFromConfig(cfg)

	if logger != nil && logLevel > 1 {
		logger.Logf("Calling GetCallerIdentity to verify AWS credentials")
	}

	// Call GetCallerIdentity to verify the credentials and get the identity
	// This operation is available in all regions and doesn't require region-specific endpoints
	getCallerIdentityOutput, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if logger != nil && logLevel > 0 {
			logger.Logf("Failed to verify AWS credentials: %v", err)
		}
		return nil, fmt.Errorf("failed to verify AWS credentials: %w", err)
	}

	if getCallerIdentityOutput.Arn == nil || getCallerIdentityOutput.Account == nil {
		if logger != nil && logLevel > 0 {
			logger.Logf("AWS returned empty ARN or Account")
		}
		return nil, errors.New("AWS returned empty ARN or Account")
	}

	// Parse the ARN to extract region and resource type
	arnParts := strings.Split(*getCallerIdentityOutput.Arn, ":")
	var region, resourceType string

	// Extract region from ARN if possible
	if len(arnParts) >= 4 {
		region = arnParts[3]
	}

	// Extract resource type from ARN
	if len(arnParts) >= 6 {
		resourceParts := strings.Split(arnParts[5], "/")
		if len(resourceParts) >= 2 {
			resourceType = resourceParts[0]
		}
	}

	if logger != nil && logLevel > 0 {
		logger.Logf("Successfully verified AWS identity: %s", *getCallerIdentityOutput.Arn)
	}

	return &CloudIdentity{
		Provider:     ProviderAWS,
		Identifier:   *getCallerIdentityOutput.Arn,
		AccountID:    *getCallerIdentityOutput.Account,
		Region:       region,
		ResourceType: resourceType,
		AdditionalClaims: map[string]string{
			"UserId": *getCallerIdentityOutput.UserId,
		},
	}, nil
}
