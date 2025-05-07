package s2iam

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/memsql/errors"
)

var debugging = false

type CloudProviderType string

// Provider Constants
const (
	ProviderAWS   CloudProviderType = "aws"
	ProviderGCP   CloudProviderType = "gcp"
	ProviderAzure CloudProviderType = "azure"
)

// Common errors
var (
	ErrNoCloudProviderDetected errors.String = "no cloud provider detected"
	ErrProviderNotDetected     errors.String = "cloud provider not detected, call Detect() first"
	ErrNoValidAuth             errors.String = "no valid cloud provider authentication found in request"
)

// CloudProviderClient is implemented for each cloud provider.
type CloudProviderClient interface {
	// Detect tests if we are executing within this cloud provider. No
	// assumption of how is made -- we could also be inside K8s. For
	// AWS, we could be on Lambda or EC2.
	Detect(ctx context.Context) error

	// GetType returns the cloud provider type as a string
	GetType() CloudProviderType

	// GetIdentityHeaders returns the headers needed to authenticate with the SingleStore auth service
	// additionalParams can be used to pass provider-specific parameters (like audience for GCP).
	// GetIdentityHeaders assumes that Detect has already been called and returned without error.
	GetIdentityHeaders(ctx context.Context, additionalParams map[string]string) (map[string]string, *CloudIdentity, error)

	// AssumeRole configures the provider to use an alternate identity
	// The roleIdentifier is provider-specific: Role ARN for AWS, service account email for GCP,
	// or managed identity ID for Azure. AssumeRole does not modify the original CloudProviderClient.
	// AssumeRole assumes that Detect has already been called and returned without error.
	AssumeRole(roleIdentifier string) CloudProviderClient
}

// CloudIdentity represents the verified identity information
type CloudIdentity struct {
	Provider CloudProviderType
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

// CloudProviderVerifier is implemented for each cloud provider.
// It is used server-side to verify requests made from clients using
// the headers returned by CloudProviderClient. The server-side code could be running on any
// cloud provider and needs to work with requests coming from other cloud providers.
type CloudProviderVerifier interface {
	// HasHeaders returns true if the incoming HTTP request has headers as created by GetIdentityHeaders
	// for the corresponding cloud provider.
	// HasHeaders is meant for use on a server and should work regardless of which cloud provider the
	// server is running on.
	HasHeaders(*http.Request) bool

	// VerifyRequest can assume that HasHeaders has returned true. It fully validates the incoming
	// headers, without trusting the client.
	VerifyRequest(context.Context, *http.Request) (*CloudIdentity, error)
}

// Logger is a simple logging interface
type Logger interface {
	Logf(format string, args ...interface{})
}

// defaultLogger provides a basic implementation that forwards to standard output
type defaultLogger struct{}

func (l defaultLogger) Logf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

// NewDefaultLogger creates a default logger instance
func NewDefaultLogger() Logger {
	return defaultLogger{}
}

// LogLevel controls the verbosity of logging
type LogLevel int

const (
	LogLevelError LogLevel = iota // Only log errors
	LogLevelInfo                  // Log info and errors
	LogLevelDebug                 // Log debug, info, and errors
)

// VerifierConfig holds configuration for cloud provider verifiers
type VerifierConfig struct {
	// AllowedAudiences is a list of allowed token audiences for GCP and Azure
	AllowedAudiences []string
	// AzureTenant is the Azure tenant ID to use for token validation
	// If empty, "common" will be used
	AzureTenant string
	// Logger provides a logging interface (if nil, default logger will be used)
	Logger Logger
	// LogLevel controls the verbosity of logging
	LogLevel LogLevel
}

// Clients is a list of available cloud provider clients
var Clients = []CloudProviderClient{
	NewAWSClient(),
	NewGCPClient(),
	NewAzureClient(),
}

// DetectProvider tries to detect which cloud provider is being used
func DetectProvider(ctx context.Context, timeout time.Duration) (CloudProviderClient, error) {
	var cancel func()
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	c := make(chan CloudProviderClient, 1) // Buffer to avoid goroutine leak
	var wg sync.WaitGroup
	wg.Add(len(Clients))
	go func() {
		wg.Wait()
		close(c)
	}()

	allErrors := make([]error, 0, len(Clients)+1)
	var errorsMu sync.Mutex

	for _, client := range Clients {
		go func() {
			defer wg.Done()
			err := client.Detect(ctx)
			if debugging {
				fmt.Println("DetectProvider ", client.GetType(), "got", err)
			}
			if err != nil {
				errorsMu.Lock()
				defer errorsMu.Unlock()
				allErrors = append(allErrors, errors.Wrapf(err, "not on %s", client.GetType()))
				return
			}
			select {
			case c <- client:
			default:
				// Another provider was already detected (unlikely)
			}
		}()
	}

	select {
	case client, ok := <-c:
		if ok {
			return client, nil
		}
		return nil, errors.WithStack(ErrNoCloudProviderDetected)
	case <-ctx.Done():
		errorsMu.Lock()
		defer errorsMu.Unlock()
		allErrors = append(allErrors, ctx.Err())
		return nil, errors.WithStack(errors.Join(allErrors...))
	}
}

type Verifiers map[CloudProviderType]CloudProviderVerifier

// CreateVerifiers creates a verifier for each cloud provider
func CreateVerifiers(ctx context.Context, config VerifierConfig) (Verifiers, error) {
	if config.Logger == nil {
		config.Logger = NewDefaultLogger()
	}

	if len(config.AllowedAudiences) == 0 {
		config.AllowedAudiences = []string{"https://auth.singlestore.com"}
	}

	// Create verifiers for each cloud provider
	awsVerifier := NewAWSVerifier(config.Logger, int(config.LogLevel))

	gcpVerifier, err := NewGCPVerifier(ctx, config.AllowedAudiences, config.Logger, int(config.LogLevel))
	if err != nil {
		return nil, errors.Errorf("failed to create GCP verifier: %w", err)
	}

	azureVerifier := NewAzureVerifier(config.AllowedAudiences, config.AzureTenant, config.Logger, int(config.LogLevel))

	verifiers := map[CloudProviderType]CloudProviderVerifier{
		ProviderAWS:   awsVerifier,
		ProviderGCP:   gcpVerifier,
		ProviderAzure: azureVerifier,
	}

	return verifiers, nil
}

// VerifyRequest verifies a request from any cloud provider
func (verifiers Verifiers) VerifyRequest(ctx context.Context, r *http.Request) (*CloudIdentity, error) {
	// Try each verifier
	for providerType, verifier := range verifiers {
		if verifier.HasHeaders(r) {
			identity, err := verifier.VerifyRequest(ctx, r)
			if err != nil {
				return nil, errors.Errorf("%s verification failed: %w", providerType, err)
			}
			return identity, nil
		}
	}

	return nil, errors.WithStack(ErrNoValidAuth)
}
