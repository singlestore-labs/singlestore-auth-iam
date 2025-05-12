package aws

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/memsql/errors"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

// AWSVerifier implements the CloudProviderVerifier interface for AWS
type AWSVerifier struct {
	logger models.Logger
	mu     sync.RWMutex
}

// awsVerifier is a singleton instance for AWSVerifier
var awsVerifier = &AWSVerifier{}

// NewAWSVerifier creates or configures the AWS verifier
func NewVerifier(logger models.Logger) models.CloudProviderVerifier {
	awsVerifier.mu.Lock()
	defer awsVerifier.mu.Unlock()

	awsVerifier.logger = logger
	return awsVerifier
}

// HasHeaders returns true if the request has AWS authentication headers
func (v *AWSVerifier) HasHeaders(r *http.Request) bool {
	return r.Header.Get("X-AWS-Access-Key-ID") != "" &&
		r.Header.Get("X-AWS-Secret-Access-Key") != "" &&
		r.Header.Get("X-AWS-Session-Token") != ""
}

// VerifyRequest validates the AWS credentials and returns the identity
func (v *AWSVerifier) VerifyRequest(ctx context.Context, r *http.Request) (*models.CloudIdentity, error) {
	v.mu.RLock()
	logger := v.logger
	v.mu.RUnlock()

	accessKeyID := r.Header.Get("X-AWS-Access-Key-ID")
	secretAccessKey := r.Header.Get("X-AWS-Secret-Access-Key")
	sessionToken := r.Header.Get("X-AWS-Session-Token")

	if accessKeyID == "" || secretAccessKey == "" || sessionToken == "" {
		if logger != nil {
			logger.Logf("Missing required AWS authentication headers")
		}
		return nil, errors.Errorf("missing required AWS authentication headers")
	}

	if logger != nil {
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
		if logger != nil {
			logger.Logf("Failed to load AWS config: %v", err)
		}
		return nil, errors.Errorf("failed to load AWS config: %w", err)
	}

	// Use us-east-1 as the default region for STS if no region is set
	// STS is a global service but requires a region in the config
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
		if logger != nil {
			logger.Logf("No region specified, using us-east-1 for STS")
		}
	}

	// Create an STS client with the configuration
	stsClient := sts.NewFromConfig(cfg)

	if logger != nil {
		logger.Logf("Calling GetCallerIdentity to verify AWS credentials")
	}

	// Call GetCallerIdentity to verify the credentials and get the identity
	// This operation is available in all regions and doesn't require region-specific endpoints
	getCallerIdentityOutput, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if logger != nil {
			logger.Logf("Failed to verify AWS credentials: %v", err)
		}
		return nil, errors.Errorf("failed to verify AWS credentials: %w", err)
	}

	if getCallerIdentityOutput.Arn == nil || getCallerIdentityOutput.Account == nil {
		if logger != nil {
			logger.Logf("AWS returned empty ARN or Account")
		}
		return nil, errors.Errorf("AWS returned empty ARN or Account")
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

	if logger != nil {
		logger.Logf("Successfully verified AWS identity: %s", *getCallerIdentityOutput.Arn)
	}

	return &models.CloudIdentity{
		Provider:     models.ProviderAWS,
		Identifier:   *getCallerIdentityOutput.Arn,
		AccountID:    *getCallerIdentityOutput.Account,
		Region:       region,
		ResourceType: resourceType,
		AdditionalClaims: map[string]string{
			"UserId": *getCallerIdentityOutput.UserId,
		},
	}, nil
}
