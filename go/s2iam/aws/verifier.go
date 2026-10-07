package aws

import (
	"context"
	"net/http"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/memsql/errors"
	"github.com/singlestore-labs/singlestore-auth-iam/go/internal/gates"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

var awsPrincipalRE = regexp.MustCompile(`^arn:aws:[a-zA-Z0-9-]+:[a-zA-Z0-9-]*:\d{12}:.+$`)

func validatePrincipal(principal string) error {
	if !gates.S2IAMValidatePrincipal.Enabled() {
		return nil
	}
	if principal == "" {
		return errors.New("principal must not be empty")
	}
	if !awsPrincipalRE.MatchString(principal) {
		return errors.Errorf("invalid AWS principal: %q", principal)
	}
	return nil
}

// AWSVerifier implements the CloudProviderVerifier interface for AWS
type AWSVerifier struct {
	logger       models.Logger
	defaultOrder []models.IdentityFormat
}

// NewVerifier configures the AWS verifier. The optional defaultOrder sets the
// identity-format ordering used when a request carries no (valid) preference;
// when empty the built-in default (models.DefaultIdentityFormats, which for AWS
// resolves to aws-arn, byte-identical to historical behavior) is used. The
// ordering may span providers; non-AWS tokens are harmlessly ignored.
func NewVerifier(logger models.Logger, defaultOrder ...models.IdentityFormat) models.CloudProviderVerifier {
	if len(defaultOrder) == 0 {
		defaultOrder = models.DefaultIdentityFormats()
	}
	return &AWSVerifier{
		logger:       logger,
		defaultOrder: defaultOrder,
	}
}

// HasHeaders returns true if the request has AWS authentication headers
func (v *AWSVerifier) HasHeaders(r *http.Request) bool {
	return r.Header.Get("X-AWS-Access-Key-ID") != "" &&
		r.Header.Get("X-AWS-Secret-Access-Key") != "" &&
		r.Header.Get("X-AWS-Session-Token") != ""
}

// VerifyRequest validates the AWS credentials and returns the identity
func (v *AWSVerifier) VerifyRequest(ctx context.Context, r *http.Request) (*models.CloudIdentity, error) {
	logger := v.logger

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

	// Extract region from the raw ARN if possible (assumed-role STS ARNs carry no
	// region, which matches historical behavior of an empty region here).
	var region string
	if parsed, err := arn.Parse(*getCallerIdentityOutput.Arn); err == nil {
		region = parsed.Region
	}

	if err := validatePrincipal(*getCallerIdentityOutput.Arn); err != nil {
		if logger != nil {
			logger.Logf("Invalid AWS principal: %v", err)
		}
		return nil, err
	}

	callerARN := *getCallerIdentityOutput.Arn
	account := *getCallerIdentityOutput.Account
	userID := aws.ToString(getCallerIdentityOutput.UserId)

	// Compute every identity format valid for this attested identity, then
	// negotiate the single chosen format against the client's preference (if any)
	// and this verifier's configured default ordering. The always-valid floor is
	// aws-arn (the raw caller ARN), so selection never fails.
	candidates := awsCandidates(callerARN, account, userID)
	clientPref := models.ParseIdentityFormatPreference(r.Header.Get(models.IdentityFormatPreferenceHeader))
	format, identifier := models.SelectIdentityFormat(candidates, clientPref, v.defaultOrder)

	if logger != nil {
		logger.Logf("Successfully verified AWS identity: %s (format: %s, attested: %s)",
			identifier, format, callerARN)
	}

	return &models.CloudIdentity{
		Provider:         models.ProviderAWS,
		Identifier:       identifier,
		IdentityFormat:   format,
		AccountID:        account,
		Region:           region,
		ResourceType:     arnResourceType(callerARN),
		AdditionalClaims: awsIdentityClaims(callerARN, userID),
		Candidates:       candidates,
	}, nil
}
