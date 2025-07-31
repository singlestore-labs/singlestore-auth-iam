package aws

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
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

const (
	getRegionURL   = "http://169.254.169.254/latest/meta-data/placement/region"
	getTokenURL    = "http://169.254.169.254/latest/api/token"
	getMetadataURL = "http://169.254.169.254/latest/meta-data/"
)

// AWSClient implements the CloudProviderClient interface for AWS
type AWSClient struct {
	stsClient *sts.Client
	roleARN   string
	identity  *models.CloudIdentity
	detected  bool
	region    string        // AWS region to use for API calls
	logger    models.Logger // Added logger field
	mu        sync.Mutex
}

func (c *AWSClient) copy() *AWSClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &AWSClient{
		stsClient: c.stsClient,
		roleARN:   c.roleARN,
		identity:  c.identity,
		detected:  c.detected,
		region:    c.region,
		logger:    c.logger,
	}
}

// NewClient returns the AWS client singleton
func NewClient(logger models.Logger) models.CloudProviderClient {
	return &AWSClient{
		logger: logger,
	}
}

// ensureRegion determines and sets the AWS region for API calls
func (c *AWSClient) ensureRegion(ctx context.Context) error {
	if c.region != "" {
		return nil
	}

	if c.logger != nil {
		c.logger.Logf("AWS ensureRegion - Determining region")
	}

	// Try environment variables first (fastest method)
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}

	// Try to get region from metadata service
	if region == "" {
		if c.logger != nil {
			c.logger.Logf("AWS ensureRegion - Trying metadata service for region")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			getRegionURL, nil)
		if err == nil {
			client := &http.Client{}
			resp, err := client.Do(req)
			if err == nil {
				defer func() {
					_ = resp.Body.Close()
				}()
				if resp.StatusCode == http.StatusOK {
					body, err := io.ReadAll(resp.Body)
					if err == nil && len(body) > 0 {
						region = string(body)
						if c.logger != nil {
							c.logger.Logf("AWS ensureRegion - Got region from metadata: %s", region)
						}
					}
				}
			}
		}
	}

	// Try SDK config if needed
	if region == "" {
		if c.logger != nil {
			c.logger.Logf("AWS ensureRegion - Trying SDK default config for region")
		}
		cfg, err := config.LoadDefaultConfig(ctx)
		if err == nil && cfg.Region != "" {
			region = cfg.Region
			if c.logger != nil {
				c.logger.Logf("AWS ensureRegion - Got region from SDK config: %s", region)
			}
		}
	}

	// Default to us-east-1 if all else fails
	if region == "" {
		region = "us-east-1"
		if c.logger != nil {
			c.logger.Logf("AWS ensureRegion - Using default region: us-east-1")
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

	if c.logger != nil {
		c.logger.Logf("AWS Detection - Starting detection")
	}

	// Check common AWS environment variables (fast check first)
	if os.Getenv("AWS_EXECUTION_ENV") != "" || os.Getenv("AWS_REGION") != "" ||
		os.Getenv("AWS_DEFAULT_REGION") != "" || os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		if c.logger != nil {
			c.logger.Logf("AWS Detection - Found AWS environment variables")
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
		getTokenURL, nil)
	if err == nil {
		tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
		client := &http.Client{}
		resp, err := client.Do(tokenReq)

		if err == nil {
			defer func() {
				_ = resp.Body.Close()
			}()
			if resp.StatusCode == http.StatusOK {
				if c.logger != nil {
					c.logger.Logf("AWS Detection - Metadata service detected")
				}
				c.detected = true // Mark detected first to avoid re-detection

				// Initialize region first (separate from full initialization)
				if err := c.ensureRegion(ctx); err != nil {
					c.detected = false // Reset detection on failure
					return err
				}

				// Verify that we can actually get AWS credentials/identity
				if err := c.testIdentityAccess(ctx); err != nil {
					c.detected = false // Reset detection on failure
					return err
				}

				// Return success - the STS client will be created lazily when needed
				return nil
			}
			if c.logger != nil {
				c.logger.Logf("AWS Detection - IMDSv2 token request failed with status: %d", resp.StatusCode)
			}
		} else {
			if c.logger != nil {
				c.logger.Logf("AWS Detection - IMDSv2 token request failed: %v", err)
			}
		}
	}

	// Fall back to direct metadata check
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getMetadataURL, nil)
	if err != nil {
		return errors.Errorf("not running on AWS: failed to detect AWS environment (no environment variables or metadata service): %w", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err == nil {
		defer func() {
			_ = resp.Body.Close()
		}()
		if resp.StatusCode == http.StatusOK {
			if c.logger != nil {
				c.logger.Logf("AWS Detection - Direct metadata service detected")
			}
			c.detected = true // Mark detected first to avoid re-detection

			// Initialize region first (separate from full initialization)
			if err := c.ensureRegion(ctx); err != nil {
				c.detected = false // Reset detection on failure
				return err
			}

			// Verify that we can actually get AWS credentials/identity
			if err := c.testIdentityAccess(ctx); err != nil {
				c.detected = false // Reset detection on failure
				return err
			}

			// Return success - the STS client will be created lazily when needed
			return nil
		}
		if c.logger != nil {
			c.logger.Logf("AWS Detection - Direct metadata check failed with status: %d", resp.StatusCode)
		}
	} else {
		if c.logger != nil {
			c.logger.Logf("AWS Detection - Direct metadata check failed: %v", err)
		}
	}

	return errors.Errorf("not running on AWS: failed to detect AWS environment (no environment variables or metadata service)")
}

// testIdentityAccess verifies that we can access AWS identity services (similar to Azure/GCP pattern)
func (c *AWSClient) testIdentityAccess(ctx context.Context) error {
	if c.logger != nil {
		c.logger.Logf("AWS Detection - Testing identity access")
	}

	// Create a short timeout context for the identity test
	testCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Initialize STS client for testing
	if err := c.initialize(testCtx); err != nil {
		if c.logger != nil {
			c.logger.Logf("AWS Detection - Failed to initialize STS client: %v", err)
		}
		return models.ErrProviderDetectedNoIdentity.Errorf("AWS detected but cannot initialize STS client: %s", err)
	}

	// Test STS GetCallerIdentity to verify we have valid credentials
	_, err := c.stsClient.GetCallerIdentity(testCtx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if c.logger != nil {
			c.logger.Logf("AWS Detection - GetCallerIdentity failed: %v", err)
		}
		return models.ErrProviderDetectedNoIdentity.Errorf("AWS detected but no valid credentials available: %s", err)
	}

	if c.logger != nil {
		c.logger.Logf("AWS Detection - Identity access verified")
	}

	return nil
}

// Initialize sets up the AWS SDK client
func (c *AWSClient) initialize(ctx context.Context) error {
	if c.logger != nil {
		c.logger.Logf("AWS Initialize - Starting initialization")
	}

	if err := c.ensureRegion(ctx); err != nil {
		return err
	}

	if c.logger != nil {
		c.logger.Logf("AWS Initialize - Using region: %s", c.region)
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(c.region))
	if err != nil {
		return errors.Errorf("failed to load AWS config: %w", err)
	}

	c.stsClient = sts.NewFromConfig(cfg)
	if c.logger != nil {
		c.logger.Logf("AWS Initialize - Successfully created STS client")
	}
	return nil
}

// GetType returns the cloud provider type
func (c *AWSClient) GetType() models.CloudProviderType {
	return models.ProviderAWS
}

// WithRegion returns a new client configured to use the specified AWS region
func (c *AWSClient) WithRegion(region string) models.CloudProviderClient {
	newClient := c.copy()
	newClient.region = region
	return newClient
}

// GetIdentityHeaders returns the headers needed to authenticate with the SingleStore auth service
func (c *AWSClient) GetIdentityHeaders(ctx context.Context, additionalParams map[string]string) (map[string]string, *models.CloudIdentity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.detected {
		return nil, nil, errors.WithStack(models.ErrProviderNotDetected)
	}

	// Initialize STS client if needed
	if c.stsClient == nil {
		if c.logger != nil {
			c.logger.Logf("AWS GetIdentityHeaders - Initializing STS client")
		}

		if err := c.initialize(ctx); err != nil {
			return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
		}
	}

	// If roleARN is provided, assume that role first
	if c.roleARN != "" {
		if c.logger != nil {
			c.logger.Logf("AWS GetIdentityHeaders - Assuming role: %s\n", c.roleARN)
		}
		// Generate a unique session name
		sessionName := fmt.Sprintf("SingleStoreAuth-%d", time.Now().Unix())

		// Assume the specified role
		assumeRoleInput := &sts.AssumeRoleInput{
			RoleArn:         &c.roleARN,
			RoleSessionName: &sessionName,
			DurationSeconds: aws.Int32(3600), // 1 hour
		}

		assumeRoleOutput, err := c.stsClient.AssumeRole(ctx, assumeRoleInput)
		if err != nil {
			return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
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
			return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
		}

		tempSTS := sts.NewFromConfig(tempCfg)
		identity, err := c.getIdentityFromSTS(ctx, tempSTS)
		if err != nil {
			return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
		}

		return headers, identity, nil
	}

	// First try to get the caller identity to check if we're already using session credentials
	if c.logger != nil {
		c.logger.Logf("AWS GetIdentityHeaders - Getting caller identity")
	}
	callerIdentity, err := c.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
	}

	// Check if we're already using session credentials
	isUsingSessionCredentials := strings.Contains(*callerIdentity.Arn, ":assumed-role/") ||
		os.Getenv("AWS_SESSION_TOKEN") != ""

	// If we're using session credentials, we can't call GetSessionToken
	// So we'll use the credentials we already have
	if isUsingSessionCredentials {
		if c.logger != nil {
			c.logger.Logf("AWS GetIdentityHeaders - Using existing session credentials")
		}

		// Get the current credentials from the SDK
		creds, err := c.stsClient.Options().Credentials.Retrieve(ctx)
		if err != nil {
			return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
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
			return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
		}

		return headers, identity, nil
	}

	// We're using permanent credentials, so we can call GetSessionToken
	if c.logger != nil {
		c.logger.Logf("AWS GetIdentityHeaders - Getting session token")
	}
	input := &sts.GetSessionTokenInput{}
	output, err := c.stsClient.GetSessionToken(ctx, input)
	if err != nil {
		return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
	}

	headers := map[string]string{
		"X-AWS-Access-Key-ID":     *output.Credentials.AccessKeyId,
		"X-AWS-Secret-Access-Key": *output.Credentials.SecretAccessKey,
		"X-AWS-Session-Token":     *output.Credentials.SessionToken,
	}

	identity, err := c.getIdentityFromSTS(ctx, c.stsClient)
	if err != nil {
		return nil, nil, errors.WithStack(models.ErrProviderDetectedNoIdentity)
	}

	return headers, identity, nil
}

// parseIdentityFromCallerIdentity converts a GetCallerIdentityOutput to a CloudIdentity
func (c *AWSClient) parseIdentityFromCallerIdentity(callerIdentity *sts.GetCallerIdentityOutput) (*models.CloudIdentity, error) {
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

	return &models.CloudIdentity{
		Provider:     models.ProviderAWS,
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
func (c *AWSClient) getIdentityFromSTS(ctx context.Context, stsClient *sts.Client) (*models.CloudIdentity, error) {
	callerIdentity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, errors.Errorf("failed to get caller identity: %w", err)
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

	return &models.CloudIdentity{
		Provider:     models.ProviderAWS,
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
func (c *AWSClient) AssumeRole(roleIdentifier string) models.CloudProviderClient {
	newClient := c.copy()
	newClient.roleARN = roleIdentifier
	return newClient
}
