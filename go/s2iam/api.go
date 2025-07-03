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
)

// Re-export from the models package to simplify usage
type (
	CloudProviderType   = models.CloudProviderType
	CloudIdentity       = models.CloudIdentity
	CloudProviderClient = models.CloudProviderClient
	Logger              = models.Logger
)

const (
	ProviderAWS   = models.ProviderAWS
	ProviderGCP   = models.ProviderGCP
	ProviderAzure = models.ProviderAzure
)

var (
	// ErrNoCloudProviderDetected is returned when no cloud provider can be detected
	ErrNoCloudProviderDetected = models.ErrNoCloudProviderDetected

	// ErrProviderNotDetected is returned when attempting to use a provider that hasn't been detected
	ErrProviderNotDetected = models.ErrProviderNotDetected

	// ErrProviderDetectedNoIdentity is returned when a provider is detected but no identity is available
	ErrProviderDetectedNoIdentity = models.ErrProviderDetectedNoIdentity

	// ErrAssumeRoleNotSupported is returned when AssumeRole is called on a provider that doesn't support it
	ErrAssumeRoleNotSupported = models.ErrAssumeRoleNotSupported
)

type JWTType = models.JWTType

const (
	DatabaseAccessJWT   = models.DatabaseAccessJWT
	APIGatewayAccessJWT = models.APIGatewayAccessJWT
)

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

// detectProviderOptions holds options for provider detection
type detectProviderOptions struct {
	logger  Logger
	clients []CloudProviderClient
	timeout time.Duration
}

// ProviderOption configures options for provider detection. All ProviderOptions
// can be used as JWTOptions.
type ProviderOption interface {
	JWTOption
	applyProviderOption(*detectProviderOptions)
}

type providerOption func(*detectProviderOptions)

func (o providerOption) applyProviderOption(opts *detectProviderOptions) {
	o(opts)
}

func (o providerOption) applyJWTOption(opts *jwtOptions) {
	o(&opts.detectProviderOptions)
}

// WithLogger sets a logger for provider detection
func WithLogger(logger Logger) ProviderOption {
	return providerOption(func(o *detectProviderOptions) {
		o.logger = logger
	})
}

// WithClients sets the list of clients to use for detection
func WithClients(clients []CloudProviderClient) ProviderOption {
	return providerOption(func(o *detectProviderOptions) {
		o.clients = clients
	})
}

// WithTimeout sets the timeout for provider detection
func WithTimeout(timeout time.Duration) ProviderOption {
	return providerOption(func(o *detectProviderOptions) {
		o.timeout = timeout
	})
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
	if options.clients == nil {
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
