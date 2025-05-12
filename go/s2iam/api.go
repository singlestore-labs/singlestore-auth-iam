// Package s2iam provides cloud provider identity detection and verification for AWS, GCP, and Azure.
// It allows applications to detect which cloud provider they're running on, obtain authentication
// headers for that provider, and verify incoming requests from cloud provider identities.
//
// Client usage:
//
//	provider, err := s2iam.DetectProvider(ctx)
//	if err != nil {
//	    // handle error
//	}
//	headers, identity, err := provider.GetIdentityHeaders(ctx, nil)
//
// Server usage:
//
//	verifiers, err := s2iam.CreateVerifiers(ctx, s2iam.VerifierConfig{})
//	if err != nil {
//	    // handle error
//	}
//	identity, err := verifiers.VerifyRequest(ctx, req)
package s2iam

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/memsql/errors"
)

const defaultTimeout = 5 * time.Second

// Logger is a simple logging interface
type Logger interface {
	Logf(format string, args ...interface{})
}

// defaultLogger provides a basic implementation that forwards to standard output
type defaultLogger struct{}

func (l defaultLogger) Logf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

// newDefaultLogger creates a default logger instance
func newDefaultLogger() Logger {
	return defaultLogger{}
}

// getLogger returns a logger based on environment settings
func getLogger() Logger {
	if os.Getenv("S2IAM_DEBUGGING") == "true" {
		return newDefaultLogger()
	}
	return nil
}

// CloudProviderType represents the type of cloud provider (AWS, GCP, or Azure)
type CloudProviderType string

// Provider Constants
const (
	ProviderAWS   CloudProviderType = "aws"
	ProviderGCP   CloudProviderType = "gcp"
	ProviderAzure CloudProviderType = "azure"
)

// Common errors returned by the s2iam package
var (
	// ErrNoCloudProviderDetected is returned when no cloud provider can be detected
	ErrNoCloudProviderDetected errors.String = "no cloud provider detected"

	// ErrProviderNotDetected is returned when attempting to use a provider that hasn't been detected
	ErrProviderNotDetected errors.String = "cloud provider not detected, call Detect() first"

	// ErrNoValidAuth is returned when no valid cloud provider authentication is found in the request
	ErrNoValidAuth errors.String = "no valid cloud provider authentication found in request"

	// ErrProviderDetectedNoIdentity is returned when a provider is detected but no identity is available
	ErrProviderDetectedNoIdentity errors.String = "cloud provider detected but no identity available"
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

// VerifierConfig holds configuration for cloud provider verifiers
type VerifierConfig struct {
	// AllowedAudiences is a list of allowed token audiences for GCP and Azure
	AllowedAudiences []string
	// AzureTenant is the Azure tenant ID to use for token validation
	// If empty, "common" will be used
	AzureTenant string
	// Logger provides a logging interface (if nil, no logging occurs)
	Logger Logger
}

// detectProviderOptions holds options for provider detection
type detectProviderOptions struct {
	logger  Logger
	clients []CloudProviderClient
	timeout time.Duration
}

// ProviderOption configures options for provider detection
type ProviderOption interface {
	applyProviderOption(*detectProviderOptions)
}

// Implementation struct for provider options
type detectOption struct {
	applyFunc func(*detectProviderOptions)
}

func (o detectOption) applyProviderOption(opts *detectProviderOptions) {
	if o.applyFunc != nil {
		o.applyFunc(opts)
	}
}

// WithLogger sets a logger for provider detection
func WithLogger(logger Logger) ProviderOption {
	return detectOption{
		applyFunc: func(o *detectProviderOptions) {
			o.logger = logger
		},
	}
}

// WithClients sets the list of clients to use for detection
func WithClients(clients []CloudProviderClient) ProviderOption {
	return detectOption{
		applyFunc: func(o *detectProviderOptions) {
			o.clients = clients
		},
	}
}

// WithTimeout sets the timeout for provider detection
func WithTimeout(timeout time.Duration) ProviderOption {
	return detectOption{
		applyFunc: func(o *detectProviderOptions) {
			o.timeout = timeout
		},
	}
}

// DetectProvider tries to detect which cloud provider is being used
func DetectProvider(ctx context.Context, opts ...ProviderOption) (CloudProviderClient, error) {
	// Initialize default options
	options := detectProviderOptions{
		timeout: defaultTimeout,
	}

	// Apply provided options
	for _, opt := range opts {
		opt.applyProviderOption(&options)
	}

	// Call implementation with prepared options
	return detectProviderImpl(ctx, options)
}

// detectProviderImpl implements the provider detection with pre-filled options
func detectProviderImpl(ctx context.Context, options detectProviderOptions) (CloudProviderClient, error) {
	// If logger is not provided, check environment variable
	if options.logger == nil && os.Getenv("S2IAM_DEBUGGING") == "true" {
		options.logger = newDefaultLogger()
	}

	// If clients are not provided, create them
	if options.clients == nil || len(options.clients) == 0 {
		options.clients = []CloudProviderClient{
			NewAWSClient(options.logger),
			NewGCPClient(options.logger),
			NewAzureClient(options.logger),
		}
	}

	// Set up timeout context
	var cancel func()
	if options.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, options.timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	c := make(chan CloudProviderClient, 1) // Buffer to avoid goroutine leak
	var wg sync.WaitGroup
	wg.Add(len(options.clients))
	go func() {
		wg.Wait()
		close(c)
	}()

	allErrors := make([]error, 0, len(options.clients)+1)
	var errorsMu sync.Mutex

	for _, client := range options.clients {
		go func(client CloudProviderClient) {
			defer wg.Done()
			err := client.Detect(ctx)
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
		}(client)
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

// Verifiers is a map of cloud provider types to their corresponding verifiers
// It provides a convenient way to store and access verifiers for different cloud providers
type Verifiers map[CloudProviderType]CloudProviderVerifier

// CreateVerifiers creates a verifier for each cloud provider
func CreateVerifiers(ctx context.Context, config VerifierConfig) (Verifiers, error) {
	// Set default logger if debugging is enabled and no logger is provided
	if config.Logger == nil && os.Getenv("S2IAM_DEBUGGING") == "true" {
		config.Logger = newDefaultLogger()
	}

	if len(config.AllowedAudiences) == 0 {
		config.AllowedAudiences = []string{"https://auth.singlestore.com"}
	}

	// Create verifiers for each cloud provider
	awsVerifier := NewAWSVerifier(config.Logger)

	gcpVerifier, err := NewGCPVerifier(ctx, config.AllowedAudiences, config.Logger)
	if err != nil {
		return nil, errors.Errorf("failed to create GCP verifier: %w", err)
	}

	azureVerifier := NewAzureVerifier(config.AllowedAudiences, config.AzureTenant, config.Logger)

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
