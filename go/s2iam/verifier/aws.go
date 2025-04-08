package verifier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// hasAWSHeaders checks if the request has AWS authentication headers
func hasAWSHeaders(r *http.Request) bool {
	return r.Header.Get("X-AWS-Access-Key-ID") != "" &&
		r.Header.Get("X-AWS-Secret-Access-Key") != "" &&
		r.Header.Get("X-AWS-Session-Token") != ""
}

// verifyAWSRequest validates AWS credentials and returns the identity
func (v *Verifier) verifyAWSRequest(ctx context.Context, r *http.Request) (*CloudIdentity, error) {
	accessKeyID := r.Header.Get("X-AWS-Access-Key-ID")
	secretAccessKey := r.Header.Get("X-AWS-Secret-Access-Key")
	sessionToken := r.Header.Get("X-AWS-Session-Token")

	if accessKeyID == "" || secretAccessKey == "" || sessionToken == "" {
		v.logError("Missing required AWS authentication headers")
		return nil, errors.New("missing required AWS authentication headers")
	}

	v.logDebug("Creating AWS config with provided credentials")
	// Create a custom AWS configuration with the provided credentials
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
		v.logError("Failed to load AWS config: %v", err)
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create an STS client with the custom configuration
	stsClient := sts.NewFromConfig(cfg)

	v.logDebug("Calling GetCallerIdentity to verify AWS credentials")
	// Call GetCallerIdentity to verify the credentials and get the identity
	getCallerIdentityOutput, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		v.logError("Failed to verify AWS credentials: %v", err)
		return nil, fmt.Errorf("failed to verify AWS credentials: %w", err)
	}

	if getCallerIdentityOutput.Arn == nil || getCallerIdentityOutput.Account == nil {
		v.logError("AWS returned empty ARN or Account")
		return nil, errors.New("AWS returned empty ARN or Account")
	}

	// Parse the ARN to extract region and resource type
	arnParts := strings.Split(*getCallerIdentityOutput.Arn, ":")
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

	v.logInfo("Successfully verified AWS identity: %s", *getCallerIdentityOutput.Arn)
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
