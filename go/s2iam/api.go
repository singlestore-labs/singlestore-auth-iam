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
	"os"
	"sync"
	"time"

	"github.com/memsql/errors"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/aws"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/azure"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/gcp"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/verifier"
)

// Re-export types from models package for backward compatibility
type (
	CloudProviderType     = models.CloudProviderType
	CloudIdentity         = models.CloudIdentity
	CloudProviderClient   = models.CloudProviderClient
	CloudProviderVerifier = models.CloudProviderVerifier
	VerifierConfig        = models.VerifierConfig
	Logger                = models.Logger
)

// Re-export provider constants
const (
	ProviderAWS   = models.ProviderAWS
	ProviderGCP   = models.ProviderGCP
	ProviderAzure = models.ProviderAzure
)

// Re-export errors
var (
	ErrNoCloudProviderDetected    = models.ErrNoCloudProviderDetected
	ErrProviderNotDetected        = models.ErrProviderNotDetected
	ErrNoValidAuth                = models.ErrNoValidAuth
	ErrProviderDetectedNoIdentity = models.ErrProviderDetectedNoIdentity
)

// Re-export JWT types
type JWTType = models.JWTType

const (
	DatabaseAccessJWT   = models.DatabaseAccessJWT
	APIGatewayAccessJWT = models.APIGatewayAccessJWT
)

// Re-export Verifiers type
type Verifiers = verifier.Verifiers

// CreateVerifiers creates a verifier for each cloud provider
func CreateVerifiers(ctx context.Context, config VerifierConfig) (Verifiers, error) {
	return verifier.CreateVerifiers(ctx, config)
}

const defaultTimeout = 5 * time.Second

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
			aws.NewClient(options.logger),
			gcp.NewClient(options.logger),
			azure.NewClient(options.logger),
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

// Export provider constructors
var (
	NewAWSClient   = aws.NewClient
	NewGCPClient   = gcp.NewClient
	NewAzureClient = azure.NewClient
)
