package models

import (
	"context"
	"net/http"

	"github.com/memsql/errors"
)

// VerifierConfig holds configuration for cloud provider verifiers
type VerifierConfig struct {
	// AllowedAudiences is a list of allowed token audiences for GCP and Azure
	AllowedAudiences []string
	// AzureTenant is the Azure tenant ID to use for token validation
	// If empty, "common" will be used
	AzureTenant string
	// Logger provides a logging interface (if nil, no logging occurs)
	Logger Logger
	// DefaultIdentityFormats overrides the identity-format ordering used when a
	// request carries no (valid) X-S2IAM-Identity-Format-Preference. It is a single
	// flat, ordered list that may span providers, mirroring the client preference
	// wire format: each token names its own provider (see IdentityFormat.Provider),
	// so only the relative order within a provider is meaningful and tokens for
	// other providers are ignored by each verifier. A provider with no token here
	// uses the built-in default from DefaultIdentityFormatOrder, which is
	// byte-identical to the historical behavior. This is how an auth-service
	// instance opts into (for example) the new AWS default
	// [aws-iam-role-arn, aws-arn] without a client change, and how versioned
	// endpoints can differ only in their default ordering.
	DefaultIdentityFormats []IdentityFormat
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

// ErrNoValidAuth is returned when no valid cloud provider authentication is found in the request
var ErrNoValidAuth errors.String = "no valid cloud provider authentication found in request"
