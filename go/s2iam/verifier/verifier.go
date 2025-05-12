// Package verifier provides aggregate verifier functionality for s2iam
package verifier

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/memsql/errors"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/aws"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/azure"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/gcp"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

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
	if config.Logger == nil && os.Getenv("S2IAM_DEBUGGING") == "true" {
		config.Logger = defaultLogger{}
	}

	if len(config.AllowedAudiences) == 0 {
		config.AllowedAudiences = []string{"https://auth.singlestore.com"}
	}

	// Create verifiers for each cloud provider
	awsVerifier := aws.NewVerifier(config.Logger)

	gcpVerifier, err := gcp.NewVerifier(ctx, config.AllowedAudiences, config.Logger)
	if err != nil {
		return nil, errors.Errorf("failed to create GCP verifier: %w", err)
	}

	azureVerifier := azure.NewVerifier(config.AllowedAudiences, config.AzureTenant, config.Logger)

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
