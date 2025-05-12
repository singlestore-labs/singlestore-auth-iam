package models

import (
	"context"
	"net/http"
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
