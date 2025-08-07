package gcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/memsql/errors"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/azure"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
	"google.golang.org/api/idtoken"
)

// GCPVerifier implements the models.CloudProviderVerifier interface for GCP
type GCPVerifier struct {
	validator        *idtoken.Validator
	allowedAudiences []string
	logger           models.Logger
	mu               sync.RWMutex // Added for concurrency safety
}

// NewVerifier creates a new GCP verifier instance
func NewVerifier(ctx context.Context, allowedAudiences []string, logger models.Logger) (models.CloudProviderVerifier, error) {
	validator, err := idtoken.NewValidator(ctx)
	if err != nil {
		return nil, errors.Errorf("failed to create GCP token validator: %w", err)
	}

	if len(allowedAudiences) == 0 {
		return nil, errors.Errorf("at least one allowed audience must be specified")
	}

	return &GCPVerifier{
		validator:        validator,
		allowedAudiences: allowedAudiences,
		logger:           logger,
	}, nil
}

// truncateString safely truncates a string to the specified length with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// HasHeaders returns true if the request has GCP authentication headers
func (v *GCPVerifier) HasHeaders(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if v.logger != nil {
		v.logger.Logf("DEBUG: GCP HasHeaders checking authorization header: %s",
			truncateString(authHeader, 20))
	}

	result := strings.HasPrefix(authHeader, "Bearer ") && !azure.HasAzureMarkers(r)

	if v.logger != nil {
		v.logger.Logf("DEBUG: GCP HasHeaders result: %v", result)
	}

	return result
}

// VerifyRequest validates GCP credentials and returns the identity
func (v *GCPVerifier) VerifyRequest(ctx context.Context, r *http.Request) (*models.CloudIdentity, error) {
	v.mu.RLock()
	validator := v.validator
	allowedAudiences := v.allowedAudiences
	logger := v.logger
	v.mu.RUnlock()

	// Always log this if logger is provided
	if logger != nil {
		logger.Logf("DEBUG: GCP VerifyRequest starting verification")
		logger.Logf("DEBUG: GCP request method: %s, path: %s", r.Method, r.URL.Path)
		logger.Logf("DEBUG: GCP request headers:")
		for name, values := range r.Header {
			logger.Logf("DEBUG:   %s: %v", name, values)
		}
	}

	authHeader := r.Header.Get("Authorization")
	if logger != nil {
		if authHeader == "" {
			logger.Logf("DEBUG: Authorization header is missing")
		} else {
			prefix := authHeader
			if len(prefix) > 20 {
				prefix = prefix[:20] + "..."
			}
			logger.Logf("DEBUG: Authorization header present: %s", prefix)
		}
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		if logger != nil {
			logger.Logf("DEBUG: Invalid GCP authentication header format - doesn't start with 'Bearer '")
		}
		return nil, errors.Errorf("invalid GCP authentication header format")
	}

	// Extract the token from the Authorization header
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		if logger != nil {
			logger.Logf("DEBUG: Empty GCP token after Bearer prefix")
		}
		return nil, errors.Errorf("empty GCP token")
	}

	if logger != nil {
		tokenPrefix := token
		if len(tokenPrefix) > 20 {
			tokenPrefix = tokenPrefix[:20] + "..."
		}
		logger.Logf("DEBUG: Token extracted: %s", tokenPrefix)
		logger.Logf("DEBUG: Token length: %d", len(token))
		logger.Logf("DEBUG: Trying to parse token without validation for debugging")

		// Try to parse the token without validation to see its contents
		parts := strings.Split(token, ".")
		if len(parts) == 3 {
			logger.Logf("DEBUG: Token has valid JWT format with 3 parts")

			// Try to decode the payload (middle part)
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				logger.Logf("DEBUG: Successfully decoded token payload: %s", string(payload))

				// Try to parse as JSON
				var claims map[string]interface{}
				if err := json.Unmarshal(payload, &claims); err == nil {
					logger.Logf("DEBUG: Token claims from raw decode:")
					for k, v := range claims {
						logger.Logf("DEBUG:   %s: %v (type: %T)", k, v, v)
					}
				} else {
					logger.Logf("DEBUG: Failed to parse payload as JSON: %v", err)
				}
			} else {
				logger.Logf("DEBUG: Failed to decode token payload: %v", err)
			}
		} else {
			logger.Logf("DEBUG: Token does not have standard JWT format with 3 parts, has %d parts", len(parts))
		}

		logger.Logf("DEBUG: Verifying GCP token with %d allowed audiences: %v", len(allowedAudiences), allowedAudiences)
	}

	// Find a matching audience
	var validationErr error
	var payload *idtoken.Payload

	for i, audience := range allowedAudiences {
		if logger != nil {
			logger.Logf("DEBUG: Trying to validate with audience #%d: %s", i+1, audience)
		}

		payloadTmp, err := validator.Validate(ctx, token, audience)
		if err == nil {
			payload = payloadTmp
			if logger != nil {
				logger.Logf("DEBUG: Successfully validated with audience: %s", audience)
			}
			break
		}
		validationErr = err
		if logger != nil {
			logger.Logf("DEBUG: Validation failed with audience %s: %v", audience, err)
		}
	}

	if payload == nil {
		if logger != nil {
			logger.Logf("DEBUG: All audience validations failed: %v", validationErr)
		}
		return nil, errors.Errorf("invalid GCP token for allowed audiences: %w", validationErr)
	}

	// Log successful token validation
	if logger != nil {
		logger.Logf("DEBUG: Token cryptographically validated successfully")
		logger.Logf("DEBUG: Validated token payload:")
		for k, v := range payload.Claims {
			logger.Logf("DEBUG:   %s: %v (type: %T)", k, v, v)
		}
		logger.Logf("DEBUG: Token issued at: %v", payload.IssuedAt)
		logger.Logf("DEBUG: Token expires at: %v", payload.Expires)
		logger.Logf("DEBUG: Token issuer: %s", payload.Issuer)
		logger.Logf("DEBUG: Token subject: %s", payload.Subject)
		logger.Logf("DEBUG: Token audience: %s", payload.Audience)
	}

	// Extract the identity information using the shared function
	if logger != nil {
		logger.Logf("DEBUG: Extracting identity from token using shared function")
	}

	return extractGCPIdentityFromToken(ctx, payload, logger)
}

// extractGCPIdentityFromToken extracts identity information from a GCP ID token payload
// This function is shared between client and verifier to ensure consistent identity extraction
// Based on actual GCP instance identity token structure. The sub field is always present.
// Optional fields like google.compute_engine are only present for specific service types.
func extractGCPIdentityFromToken(ctx context.Context, payload *idtoken.Payload, logger models.Logger) (*models.CloudIdentity, error) {
	// Get the numeric service account ID from sub - this is always the AccountID
	sub, ok := payload.Claims["sub"].(string)
	if !ok || sub == "" {
		return nil, errors.Errorf("no subject claim found in GCP token")
	}

	// Determine the primary identifier - prefer verified email if available, fallback to sub
	identifier := sub // Default to numeric ID
	if email, ok := payload.Claims["email"].(string); ok && email != "" {
		if emailVerified, ok := payload.Claims["email_verified"].(bool); ok && emailVerified {
			identifier = email
			if logger != nil {
				logger.Logf("DEBUG: Using verified email claim as identifier: %s", identifier)
			}
		} else {
			if logger != nil {
				logger.Logf("DEBUG: Email present but not verified, using subject: %s", sub)
			}
		}
	} else {
		if logger != nil {
			logger.Logf("DEBUG: Using subject claim as identifier: %s", sub)
		}
	}

	// Extract region and resource type from google section if available
	region := ""
	resourceType := "instance" // Default
	if google, ok := payload.Claims["google"].(map[string]interface{}); ok {
		// Extract all keys from google section, sort them, and take the first
		var keys []string
		for key := range google {
			keys = append(keys, key)
		}
		if len(keys) > 0 {
			// Sort keys and take the first one as resource type
			sort.Strings(keys)
			resourceType = keys[0]

			// Try to extract region if this is compute_engine
			if resourceType == "compute_engine" {
				if computeEngine, ok := google["compute_engine"].(map[string]interface{}); ok {
					if zone, ok := computeEngine["zone"].(string); ok && zone != "" {
						// Extract region from zone (e.g., us-east4-c -> us-east4)
						parts := strings.Split(zone, "-")
						if len(parts) >= 3 {
							region = strings.Join(parts[:len(parts)-1], "-")
						}
						if logger != nil {
							logger.Logf("DEBUG: Extracted region from zone: %s -> %s", zone, region)
						}
					}
				}
			}
		}
		if logger != nil {
			logger.Logf("DEBUG: Detected resource type: %s (from keys: %v)", resourceType, keys)
		}
	}

	// Prepare additional claims - include all string claims for debugging/metadata
	additionalClaims := make(map[string]string)
	for k, v := range payload.Claims {
		if str, ok := v.(string); ok {
			additionalClaims[k] = str
		}
	}

	return &models.CloudIdentity{
		Provider:         models.ProviderGCP,
		Identifier:       identifier,
		AccountID:        sub,
		Region:           region,       // May be empty for non-Compute Engine services
		ResourceType:     resourceType, // Determined from google section
		AdditionalClaims: additionalClaims,
	}, nil
}
