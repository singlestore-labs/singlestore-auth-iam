// Package verifier provides aggregate verifier functionality for s2iam
//
// Server usage:
//
//	verifiers, err := verifier.CreateVerifiers(ctx, s2iam.VerifierConfig{})
//	if err != nil {
//	    // handle error
//	}
//	identity, err := verifiers.VerifyRequest(ctx, req)
package s2verifier

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/memsql/errors"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/aws"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/azure"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/gcp"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

// Re-export from the models package to simplify usage
type (
	CloudProviderVerifier = models.CloudProviderVerifier
	VerifierConfig        = models.VerifierConfig
)

// ErrNoValidAuth is returned when no valid cloud provider authentication is found in the request
var ErrNoValidAuth = models.ErrNoValidAuth

// defaultLogger provides a basic implementation that forwards to standard output
type defaultLogger struct{}

func (l defaultLogger) Logf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

// Verifiers is a map of cloud provider types to their corresponding verifiers
// It provides a convenient way to store and access verifiers for different cloud providers
type Verifiers map[models.CloudProviderType]models.CloudProviderVerifier

// CreateVerifiers creates a verifier for each cloud provider
func CreateVerifiers(ctx context.Context, config models.VerifierConfig) (Verifiers, error) {
	// Set default logger if debugging is enabled and no logger is provided
	if config.Logger == nil && strings.EqualFold(os.Getenv("S2IAM_DEBUGGING"), "true") {
		config.Logger = defaultLogger{}
	}

	if len(config.AllowedAudiences) == 0 {
		config.AllowedAudiences = []string{"https://authsvc.singlestore.com"}
	}

	// Pass the operator's configured override ordering (may be empty) to every
	// verifier. SelectIdentityFormat concatenates client preference, this override,
	// and the static built-in default, so a provider the operator didn't mention
	// still keeps its historical default. The full flat list is used unfiltered —
	// negotiation only ever returns a format valid for the identity at hand, so
	// tokens for other providers are harmlessly ignored.
	awsVerifier := aws.NewVerifier(config.Logger, config.DefaultIdentityFormats...)

	gcpVerifier, err := gcp.NewVerifier(ctx, config.AllowedAudiences, config.Logger, config.DefaultIdentityFormats...)
	if err != nil {
		return nil, errors.Errorf("failed to create GCP verifier: %w", err)
	}

	azureVerifier := azure.NewVerifier(config.AllowedAudiences, config.AzureTenant, config.Logger, config.DefaultIdentityFormats...)

	verifiers := map[models.CloudProviderType]models.CloudProviderVerifier{
		models.ProviderAWS:   awsVerifier,
		models.ProviderGCP:   gcpVerifier,
		models.ProviderAzure: azureVerifier,
	}

	return verifiers, nil
}

// VerifyRequest verifies a request from any cloud provider
func (verifiers Verifiers) VerifyRequest(ctx context.Context, r *http.Request) (*models.CloudIdentity, error) {
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

	return nil, errors.WithStack(models.ErrNoValidAuth)
}
