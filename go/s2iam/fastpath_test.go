package s2iam_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"
)

// TestFastPathDetection tests that fast-path detection using environment variables
// produces the same results as full detection
func TestFastPathDetection(t *testing.T) {
	// Skip on NO_ROLE hosts since we need working cloud provider detection
	if os.Getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") != "" {
		t.Skip("test requires working cloud role - skipped on no-role hosts")
	}

	// Skip if not in a cloud environment - this should work on both role and no-role hosts
	expectCloudProviderDetected(t)

	// First, do normal detection to get the baseline
	normalClient, err := s2iam.DetectProvider(context.Background(),
		s2iam.WithLogger(t),
		s2iam.WithTimeout(time.Second*10))
	require.NoError(t, err, "Normal detection should succeed")

	providerType := normalClient.GetType()
	t.Logf("Detected provider: %s", providerType)

	// Determine what environment variables should enable fast-path detection
	var envVarsToSet map[string]string

	switch providerType {
	case s2iam.ProviderAWS:
		// For AWS, we can derive the region and set AWS environment variables
		// that would trigger fast-path detection
		envVarsToSet = map[string]string{
			"AWS_EXECUTION_ENV": "AWS_EC2", // Generic indicator we're on AWS
		}

		// Try to get region from existing environment or metadata
		if region := os.Getenv("AWS_REGION"); region != "" {
			envVarsToSet["AWS_REGION"] = region
		} else if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
			envVarsToSet["AWS_REGION"] = region
		}

	case s2iam.ProviderGCP:
		// For GCP, set GCE_METADATA_HOST to trigger fast-path
		envVarsToSet = map[string]string{
			"GCE_METADATA_HOST": "metadata.google.internal",
		}

	case s2iam.ProviderAzure:
		// For Azure, set AZURE_ENV to trigger fast-path
		envVarsToSet = map[string]string{
			"AZURE_ENV": "AzureCloud",
		}

	default:
		t.Fatalf("Unknown provider type: %v", providerType)
	}

	for key, value := range envVarsToSet {
		t.Setenv(key, value) // This automatically restores the original value after the test
		t.Logf("Set %s=%s for fast-path detection", key, value)
	}

	// Now test fast-path detection
	fastPathClient, err := s2iam.DetectProvider(context.Background(),
		s2iam.WithLogger(t),
		s2iam.WithTimeout(time.Second*5)) // Shorter timeout since fast-path should be quick

	// On NO_ROLE hosts, fast-path detection might fail if it tries to access identity metadata
	if os.Getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") != "" && err != nil {
		// Fast-path detection failed on NO_ROLE host - validate it's the expected error type
		if errors.Is(err, s2iam.ErrNoCloudProviderDetected) || errors.Is(err, s2iam.ErrProviderDetectedNoIdentity) {
			t.Logf("Fast-path detection failed on NO_ROLE host with valid error as expected: %v", err)
			return
		}
		// If it's not a valid NO_ROLE error, that's a test failure
		require.Fail(t, "Fast-path detection failed on NO_ROLE host with unexpected error type. "+
			"Expected ErrNoCloudProviderDetected or ErrProviderDetectedNoIdentity, got: %+v", err)
		return
	}

	require.NoError(t, err, "Fast-path detection should succeed")

	// Verify both detections give the same provider type
	assert.Equal(t, normalClient.GetType(), fastPathClient.GetType(),
		"Fast-path detection should give same provider type as normal detection")

	t.Logf("Fast-path detection test passed for %s", providerType)
	t.Logf("Normal detection provider: %s", normalClient.GetType())
	t.Logf("Fast-path detection provider: %s", fastPathClient.GetType())

	// Skip header testing on NO_ROLE hosts where GetIdentityHeaders is expected to fail
	if os.Getenv("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE") != "" {
		t.Logf("Skipping header testing on NO_ROLE host")
		return
	}

	// Test that both clients work equivalently using shared test function
	testHappyPath(t, fastPathClient)
}
