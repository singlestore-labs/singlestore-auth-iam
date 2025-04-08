package verifier

import (
	"context"
	"fmt"
	"net/http"

	"google.golang.org/api/idtoken"
)

// CloudIdentity represents the verified identity information
type CloudIdentity struct {
	Provider string // "aws", "gcp", or "azure"
	// The identifier will be:
	// - AWS: ARN of the IAM role/user
	// - GCP: Project number + instance ID + service account email
	// - Azure: Principal ID (object ID of the managed identity)
	Identifier string
	// Additional fields that might be useful for authorization decisions
	AccountID        string            // AWS account ID or GCP project ID
	Region           string            // Cloud provider region (when available)
	ResourceType     string            // Type of resource (VM, function, etc.)
	AdditionalClaims map[string]string // Any additional relevant claims from tokens
}

// CloudVerifier defines the interface for cloud provider identity verification
// This interface can be used for mocking in tests
type CloudVerifier interface {
	// VerifyRequest validates the cloud provider authentication in the request
	// and returns the cloud identity information or an error
	VerifyRequest(ctx context.Context, r *http.Request) (*CloudIdentity, error)

	// VerifyRequestAndGetBody validates the cloud provider authentication and returns the request body
	VerifyRequestAndGetBody(ctx context.Context, r *http.Request) (*CloudIdentity, []byte, error)
}

// Ensure that the concrete Verifier implements the CloudVerifier interface
var _ CloudVerifier = (*Verifier)(nil)

// LogLevel controls the verbosity of logging
type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelInfo
	LogLevelDebug
)

// Logger is a simple logging interface
type Logger interface {
	Logf(format string, args ...interface{})
}

// DefaultLogger implements the Logger interface
type DefaultLogger struct {
	Level LogLevel
}

// Logf logs a message with the specified format and arguments
func (l *DefaultLogger) Logf(format string, args ...interface{}) {
	// All logs are prefixed with [IAM]
	prefixedFormat := "[IAM] " + format
	fmt.Printf(prefixedFormat+"\n", args...)
}

// VerifierConfig holds configuration for the verifier
type VerifierConfig struct {
	// AllowedAudiences is a list of allowed token audiences
	AllowedAudiences []string
	// AzureTenant is the Azure tenant ID to use for token validation
	// If empty, "common" will be used
	AzureTenant string
	// EnableLegacyModeAWS allows pre-STS credential verification (less secure)
	EnableLegacyModeAWS bool
	// Logger provides a logging interface (if nil, default logger will be used)
	Logger Logger
	// LogLevel controls the verbosity of logging
	LogLevel LogLevel
}

// Verifier handles cloud provider authentication verification
type Verifier struct {
	config       VerifierConfig
	azureJWKSMgr *jwksManager
	gcpValidator *idtoken.Validator
	logger       Logger
}

// NewVerifier creates a new verifier with the given configuration
func NewVerifier(ctx context.Context, config VerifierConfig) (*Verifier, error) {
	if len(config.AllowedAudiences) == 0 {
		config.AllowedAudiences = []string{"https://auth.singlestore.com"}
	}

	if config.AzureTenant == "" {
		config.AzureTenant = defaultAzureTenant
	}

	if config.Logger == nil {
		config.Logger = &DefaultLogger{Level: config.LogLevel}
	}

	// Create a GCP token validator
	gcpValidator, err := idtoken.NewValidator(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP token validator: %w", err)
	}

	v := &Verifier{
		config:       config,
		azureJWKSMgr: newJWKSManager(config.AzureTenant),
		gcpValidator: gcpValidator,
		logger:       config.Logger,
	}

	v.logInfo("Verifier initialized with audiences: %v", config.AllowedAudiences)
	return v, nil
}
