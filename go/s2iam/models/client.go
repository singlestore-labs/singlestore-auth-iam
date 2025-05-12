// Package models contains shared types and interfaces for the s2iam package
package models

import (
	"context"
	"time"

	"github.com/memsql/errors"
)

// CloudProviderType represents the type of cloud provider (AWS, GCP, or Azure)
type CloudProviderType string

// Provider Constants
const (
	ProviderAWS   CloudProviderType = "aws"
	ProviderGCP   CloudProviderType = "gcp"
	ProviderAzure CloudProviderType = "azure"
)

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

// Logger is a simple logging interface
type Logger interface {
	Logf(format string, args ...interface{})
}

// DetectProviderOptions holds options for provider detection
type DetectProviderOptions struct {
	Logger  Logger
	Clients []CloudProviderClient
	Timeout time.Duration
}

// JWTType represents the type of JWT requested from the authentication service
type JWTType string

const (
	// DatabaseAccessJWT is used to request a JWT for accessing the database
	DatabaseAccessJWT JWTType = "database"

	// APIGatewayAccessJWT is used to request a JWT for accessing the API gateway
	APIGatewayAccessJWT JWTType = "api"
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

// Common errors returned by the s2iam package
var (
	// ErrNoCloudProviderDetected is returned when no cloud provider can be detected
	ErrNoCloudProviderDetected errors.String = "no cloud provider detected"

	// ErrProviderNotDetected is returned when attempting to use a provider that hasn't been detected
	ErrProviderNotDetected errors.String = "cloud provider not detected, call Detect() first"

	// ErrProviderDetectedNoIdentity is returned when a provider is detected but no identity is available
	ErrProviderDetectedNoIdentity errors.String = "cloud provider detected but no identity available"
)
