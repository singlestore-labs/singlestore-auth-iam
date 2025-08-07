package testhelp

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"
)

// MaybeParallel calls t.Parallel() unless we're running Azure tests in a cloud environment.
// Azure has rate limiting issues that cause HTTP 429 errors when tests run in parallel.
// This helper checks all three cloud test environment variables to determine if we should
// avoid parallel execution.
func MaybeParallel(t *testing.T) {
	// Check if we're running in any cloud test environment
	cloudProvider := os.Getenv("S2IAM_TEST_CLOUD_PROVIDER")
	noRoleProvider := os.Getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")

	// If we're testing Azure in any cloud configuration, don't run in parallel
	// to avoid rate limiting (HTTP 429 "Temporarily throttled, too many requests")
	if cloudProvider == "azure" || noRoleProvider == "azure" {
		return // Don't call t.Parallel() for Azure
	}

	// There is only one assumeRole test right now so we'll ignore it. Also, it's hard to
	// know if we're on azure with assumeRole.

	// For all other cases (local tests, AWS, GCP), run in parallel
	t.Parallel()
}

// ExpectCloudProviderDetected detects cloud provider and skips test if none found.
// If S2IAM_TEST_CLOUD_PROVIDER, S2IAM_TEST_ASSUME_ROLE, or S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE is set,
// fail instead of skip (test environment should be configured).
func ExpectCloudProviderDetected(t *testing.T) s2iam.CloudProviderClient {
	if os.Getenv("S2IAM_TEST_CLOUD_PROVIDER") == "" && os.Getenv("S2IAM_TEST_ASSUME_ROLE") == "" && os.Getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") == "" {
		t.Skip("cloud provider required")
	}
	client, err := s2iam.DetectProvider(context.Background(),
		s2iam.WithLogger(t),
		s2iam.WithTimeout(time.Second*5))
	if err != nil {
		require.Truef(t, errors.Is(err, s2iam.ErrProviderDetectedNoIdentity), "error other than no identity %+v", err)
		t.Skip("cloud provider detected no identity")
	}
	return client
}

// RequireCloudRole requires cloud provider with working role/identity (not just detection).
// This is for tests that need to actually use the cloud identity, not just detect the provider.
func RequireCloudRole(t *testing.T) s2iam.CloudProviderClient {
	if os.Getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") != "" {
		t.Skip("cloud role required")
	}
	return ExpectCloudProviderDetected(t)
}
