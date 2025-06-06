package gcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
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

// gcpVerifier is a singleton instance for GCPVerifier
var gcpVerifier = &GCPVerifier{}

// NewGCPVerifier creates or configures the GCP verifier
func NewVerifier(ctx context.Context, allowedAudiences []string, logger models.Logger) (models.CloudProviderVerifier, error) {
	gcpVerifier.mu.Lock()
	defer gcpVerifier.mu.Unlock()

	// Create a new validator if it doesn't exist or if contexts/configs have changed
	if gcpVerifier.validator == nil {
		validator, err := idtoken.NewValidator(ctx)
		if err != nil {
			return nil, errors.Errorf("failed to create GCP token validator: %w", err)
		}
		gcpVerifier.validator = validator
	}

	// Update configuration
	gcpVerifier.allowedAudiences = allowedAudiences
	gcpVerifier.logger = logger

	return gcpVerifier, nil
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

	// Extract the identity information from the token payload
	if logger != nil {
		logger.Logf("DEBUG: Extracting identifiers from token")
	}

	projectID, instanceID, serviceAccount, zone, err := v.extractIdentifiers(payload)
	if err != nil {
		if logger != nil {
			logger.Logf("DEBUG: Failed to extract identifiers from token: %v", err)
		}
		return nil, err
	}

	// Log the extracted identifiers
	if logger != nil {
		logger.Logf("DEBUG: Successfully extracted identifiers:")
		logger.Logf("DEBUG:   projectID: %s", projectID)
		logger.Logf("DEBUG:   instanceID: %s", instanceID)
		logger.Logf("DEBUG:   serviceAccount: %s", serviceAccount)
		logger.Logf("DEBUG:   zone: %s", zone)
	}

	// Determine the primary identifier for this identity
	identifier := ""

	// Prefer using subject as identifier if present
	if sub, ok := payload.Claims["sub"].(string); ok && sub != "" {
		identifier = sub
		if logger != nil {
			logger.Logf("DEBUG: Using subject claim as primary identifier: %s", identifier)
		}
	} else if serviceAccount != "" {
		// Fall back to service account email if no subject
		identifier = serviceAccount
		if logger != nil {
			logger.Logf("DEBUG: Using service account email as primary identifier: %s", identifier)
		}
	} else {
		// Construct a basic identifier using available information
		identifier = fmt.Sprintf("projects/%s/instances/%s", projectID, instanceID)
		if logger != nil {
			logger.Logf("DEBUG: Using constructed identifier: %s", identifier)
		}
	}

	resourceType := "instance"
	if serviceAccount != "" {
		if strings.Contains(serviceAccount, "cloud-function") {
			resourceType = "function"
			if logger != nil {
				logger.Logf("DEBUG: Detected resource type: function")
			}
		} else if strings.Contains(serviceAccount, "app-engine") {
			resourceType = "appengine"
			if logger != nil {
				logger.Logf("DEBUG: Detected resource type: appengine")
			}
		} else {
			if logger != nil {
				logger.Logf("DEBUG: Using default resource type: instance")
			}
		}
	}

	region := ""
	if zone != "" {
		// Extract region from zone (e.g., us-central1-a -> us-central1)
		parts := strings.Split(zone, "-")
		if len(parts) >= 3 {
			region = strings.Join(parts[:len(parts)-1], "-")
			if logger != nil {
				logger.Logf("DEBUG: Extracted region from zone: %s", region)
			}
		}
	}

	// Prepare additional claims
	additionalClaims := make(map[string]string)
	for k, v := range payload.Claims {
		if str, ok := v.(string); ok {
			additionalClaims[k] = str
		}
	}

	if logger != nil {
		logger.Logf("DEBUG: Successfully verified GCP identity: %s", identifier)
		logger.Logf("DEBUG: Returning CloudIdentity with Provider=%s, Identifier=%s, AccountID=%s, Region=%s, ResourceType=%s",
			models.ProviderGCP, identifier, projectID, region, resourceType)
	}

	return &models.CloudIdentity{
		Provider:         models.ProviderGCP,
		Identifier:       identifier,
		AccountID:        projectID,
		Region:           region,
		ResourceType:     resourceType,
		AdditionalClaims: additionalClaims,
	}, nil
}

// extractIdentifiers extracts identity information from the token payload
// Instead of requiring a specific project ID format, we use available claims
// to create a unique, stable identifier for the authenticated entity
func (v *GCPVerifier) extractIdentifiers(payload *idtoken.Payload) (projectID, instanceID, serviceAccount, zone string, err error) {
	// Always log claims, regardless of log level
	if v.logger != nil {
		v.logger.Logf("DEBUG: Token payload claims in extractIdentifiers:")
		for k, val := range payload.Claims {
			v.logger.Logf("DEBUG:   %s: %v (type: %T)", k, val, val)
		}
		v.logger.Logf("DEBUG: Standard JWT fields:")
		v.logger.Logf("DEBUG:   Issuer: %s", payload.Issuer)
		v.logger.Logf("DEBUG:   Subject: %s", payload.Subject)
		v.logger.Logf("DEBUG:   Audience: %s", payload.Audience)
		v.logger.Logf("DEBUG:   Expiration: %v", payload.Expires)
		v.logger.Logf("DEBUG:   IssuedAt: %v", payload.IssuedAt)
	}

	// First try to get a project ID using our existing methods
	if v.logger != nil {
		v.logger.Logf("DEBUG: Attempting to extract project ID from token claims")
	}

	projectID = tryExtractProjectID(payload, v.logger)

	if v.logger != nil {
		if projectID == "" {
			v.logger.Logf("DEBUG: No project ID extracted from token claims")
		} else {
			v.logger.Logf("DEBUG: Successfully extracted project ID: %s", projectID)
		}
	}

	// If no project ID found but we have a subject claim, use it to derive a stable identifier
	// This allows us to work with tokens that don't contain explicit project IDs
	if projectID == "" {
		if v.logger != nil {
			v.logger.Logf("DEBUG: No project ID found, checking for subject/email for identification")
		}

		sub, hasSub := payload.Claims["sub"].(string)
		email, hasEmail := payload.Claims["email"].(string)

		if hasSub {
			v.logger.Logf("DEBUG: Found subject claim: %s", sub)
		} else {
			v.logger.Logf("DEBUG: No subject claim found")
		}

		if hasEmail {
			v.logger.Logf("DEBUG: Found email claim: %s", email)
		} else {
			v.logger.Logf("DEBUG: No email claim found")
		}

		// If we have a subject or email, we can proceed
		if hasSub || hasEmail {
			if v.logger != nil {
				v.logger.Logf("DEBUG: Using subject/email for identification")
			}

			// Create a stable derived identifier based on available claims
			// For account ID, we'll use the first part of the email if available
			if hasEmail && strings.Contains(email, "@") {
				v.logger.Logf("DEBUG: Trying to extract project ID from email: %s", email)

				parts := strings.Split(email, "@")
				if len(parts) > 1 && strings.Contains(parts[1], ".") {
					v.logger.Logf("DEBUG: Email parsed into: %s @ %s", parts[0], parts[1])

					// Try to extract project info from email domain
					if strings.Contains(parts[1], ".iam.gserviceaccount.com") {
						v.logger.Logf("DEBUG: Email looks like service account email")
						domainParts := strings.Split(parts[1], ".")
						v.logger.Logf("DEBUG: Domain parts: %v", domainParts)

						if len(domainParts) > 0 {
							projectID = domainParts[0]
							v.logger.Logf("DEBUG: Extracted project ID from service account email: %s", projectID)
						}
					} else if strings.HasSuffix(parts[0], "-compute") &&
						strings.HasPrefix(parts[1], "developer.gserviceaccount.com") {
						// Format: PROJECT_NUMBER-compute@developer.gserviceaccount.com
						v.logger.Logf("DEBUG: Email looks like compute service account")
						projectNum := strings.TrimSuffix(parts[0], "-compute")
						if projectNum != "" {
							projectID = projectNum
							v.logger.Logf("DEBUG: Extracted project ID from compute email: %s", projectID)
						}
					} else {
						v.logger.Logf("DEBUG: Email format doesn't match known service account patterns")
					}
				}
			}

			// If we still don't have a project ID but have a subject,
			// try to extract from the subject string directly
			if projectID == "" && hasSub {
				v.logger.Logf("DEBUG: Trying to extract project ID from subject: %s", sub)
				projectID = extractProjectFromSub(sub, v.logger)

				if projectID == "" {
					// Last resort: Use subject as identifier but error
					v.logger.Logf("DEBUG ERROR: Could not extract project ID from subject")
					return "", "", "", "", errors.Errorf("project identifier not found in GCP token")
				}
			}
		} else {
			// No subject or email means we don't have any way to identify the entity
			if v.logger != nil {
				v.logger.Logf("DEBUG ERROR: No identifying information found in GCP token claims")
			}
			return "", "", "", "", errors.Errorf("no identifying information found in GCP token")
		}
	}

	// Extract the instance ID
	if val, ok := payload.Claims["google/compute_engine/instance_id"].(string); ok {
		instanceID = val
		if v.logger != nil {
			v.logger.Logf("DEBUG: Found instance ID: %s", instanceID)
		}
	} else {
		// For non-GCE resources, generate a placeholder
		instanceID = "non-gce-resource"
		if v.logger != nil {
			v.logger.Logf("DEBUG: No instance ID found, using placeholder: %s", instanceID)
		}
	}

	// Extract service account email
	if val, ok := payload.Claims["email"].(string); ok {
		serviceAccount = val
		if v.logger != nil {
			v.logger.Logf("DEBUG: Found service account email: %s", serviceAccount)
		}
	} else {
		if v.logger != nil {
			v.logger.Logf("DEBUG: No service account email found")
		}
	}

	// Extract zone if present
	if val, ok := payload.Claims["google/compute_engine/zone"].(string); ok {
		zone = val
		if v.logger != nil {
			v.logger.Logf("DEBUG: Found zone: %s", zone)
		}
	} else {
		if v.logger != nil {
			v.logger.Logf("DEBUG: No zone information found")
		}
	}

	// Use subject as the primary component of our identifier if present
	sub, hasSub := payload.Claims["sub"].(string)
	identifier := ""

	if hasSub {
		// Use the full subject as the identifier base
		identifier = sub
		if v.logger != nil {
			v.logger.Logf("DEBUG: Using subject as primary identifier: %s", identifier)
		}
	} else if serviceAccount != "" {
		// Fall back to service account email if no subject
		identifier = serviceAccount
		if v.logger != nil {
			v.logger.Logf("DEBUG: Using service account as primary identifier: %s", identifier)
		}
	} else {
		// If neither is available, construct a basic identifier
		identifier = "projects/" + projectID + "/instances/" + instanceID
		if v.logger != nil {
			v.logger.Logf("DEBUG: Constructed identifier: %s", identifier)
		}
	}

	if v.logger != nil {
		v.logger.Logf("DEBUG: Final extracted values:")
		v.logger.Logf("DEBUG:   identifier: %s", identifier)
		v.logger.Logf("DEBUG:   projectID: %s", projectID)
		v.logger.Logf("DEBUG:   instanceID: %s", instanceID)
		v.logger.Logf("DEBUG:   serviceAccount: %s", serviceAccount)
		v.logger.Logf("DEBUG:   zone: %s", zone)
	}

	return projectID, instanceID, serviceAccount, zone, nil
}

// tryExtractProjectID attempts to extract project ID from various token claims
func tryExtractProjectID(payload *idtoken.Payload, logger models.Logger) string {
	// Try multiple approaches to extract project ID from token claims
	if logger != nil {
		logger.Logf("DEBUG: tryExtractProjectID starting")
	}

	// Standard GCP metadata claims
	if val, ok := payload.Claims["google/compute_engine/project_number"].(string); ok {
		if logger != nil {
			logger.Logf("DEBUG: Found project number in google/compute_engine/project_number: %s", val)
		}
		return val
	} else if logger != nil {
		logger.Logf("DEBUG: No google/compute_engine/project_number claim found")
	}

	if val, ok := payload.Claims["project_id"].(string); ok {
		if logger != nil {
			logger.Logf("DEBUG: Found project_id claim: %s", val)
		}
		return val
	} else if logger != nil {
		logger.Logf("DEBUG: No project_id claim found")
	}

	// Check for the 'azp' (authorized party) claim which sometimes contains project info
	if val, ok := payload.Claims["azp"].(string); ok {
		if logger != nil {
			logger.Logf("DEBUG: Found azp claim: %s", val)
		}

		// For service accounts, azp is often in the format:
		// [PROJECT_NUMBER]-compute@developer.gserviceaccount.com
		if parts := strings.Split(val, "-"); len(parts) > 1 && strings.HasSuffix(parts[1], "compute") {
			if logger != nil {
				logger.Logf("DEBUG: azp claim looks like compute service account")
				logger.Logf("DEBUG: azp parts: %v", parts)
				logger.Logf("DEBUG: Extracted project from azp: %s", parts[0])
			}
			return parts[0]
		} else if logger != nil {
			logger.Logf("DEBUG: azp claim doesn't match expected pattern")
		}
	} else if logger != nil {
		logger.Logf("DEBUG: No azp claim found")
	}

	// Try subject claim for project info
	if val, ok := payload.Claims["sub"].(string); ok {
		if logger != nil {
			logger.Logf("DEBUG: Found sub claim: %s", val)
		}

		projectID := extractProjectFromSub(val, logger)
		if projectID != "" {
			if logger != nil {
				logger.Logf("DEBUG: Extracted project from sub: %s", projectID)
			}
			return projectID
		} else if logger != nil {
			logger.Logf("DEBUG: Could not extract project from sub")
		}
	} else if logger != nil {
		logger.Logf("DEBUG: No sub claim found")
	}

	// Try email claim for service accounts
	if val, ok := payload.Claims["email"].(string); ok && strings.Contains(val, "@") {
		if logger != nil {
			logger.Logf("DEBUG: Found email claim: %s", val)
		}

		parts := strings.Split(val, "@")
		if len(parts) > 1 && strings.Contains(parts[1], ".") {
			if logger != nil {
				logger.Logf("DEBUG: Email parts: %s @ %s", parts[0], parts[1])
			}

			// Service account emails can be:
			// [NAME]@[PROJECT_ID].iam.gserviceaccount.com
			// or
			// [PROJECT_NUMBER]-compute@developer.gserviceaccount.com

			// Check for the second format first
			if strings.HasSuffix(parts[0], "-compute") && strings.HasPrefix(parts[1], "developer.gserviceaccount.com") {
				projectNum := strings.TrimSuffix(parts[0], "-compute")
				if logger != nil {
					logger.Logf("DEBUG: Email matches compute service account pattern")
					logger.Logf("DEBUG: Extracted project from email: %s", projectNum)
				}
				return projectNum
			} else if logger != nil {
				logger.Logf("DEBUG: Email doesn't match compute service account pattern")
			}

			// Check for the first format
			if strings.Contains(parts[1], ".iam.gserviceaccount.com") {
				projectParts := strings.Split(parts[1], ".")
				if len(projectParts) > 0 {
					if logger != nil {
						logger.Logf("DEBUG: Email matches service account pattern")
						logger.Logf("DEBUG: Domain parts: %v", projectParts)
						logger.Logf("DEBUG: Extracted project from email domain: %s", projectParts[0])
					}
					return projectParts[0]
				}
			} else if logger != nil {
				logger.Logf("DEBUG: Email doesn't match service account pattern")
			}
		}
	} else if logger != nil {
		logger.Logf("DEBUG: No email claim found or doesn't contain @")
	}

	// Try audience claim as a last resort
	if val, ok := payload.Claims["aud"].(string); ok {
		if logger != nil {
			logger.Logf("DEBUG: Found aud claim: %s", val)
		}

		projectID := extractProjectFromSub(val, logger)
		if projectID != "" {
			if logger != nil {
				logger.Logf("DEBUG: Extracted project from aud: %s", projectID)
			}
			return projectID
		} else if logger != nil {
			logger.Logf("DEBUG: Could not extract project from aud")
		}
	} else if logger != nil {
		logger.Logf("DEBUG: No aud claim found")
	}

	if logger != nil {
		logger.Logf("DEBUG: Failed to extract project ID from any claim")
	}
	return ""
}

// extractProjectFromSub tries to extract project ID from a subject string
func extractProjectFromSub(sub string, logger models.Logger) string {
	if logger != nil {
		logger.Logf("DEBUG: extractProjectFromSub analyzing: %s", sub)
	}

	// Check for 'projects/' pattern
	if strings.Contains(sub, "projects/") {
		if logger != nil {
			logger.Logf("DEBUG: Subject contains 'projects/'")
		}

		parts := strings.Split(sub, "/")
		if logger != nil {
			logger.Logf("DEBUG: Subject parts: %v", parts)
		}

		for i, part := range parts {
			if part == "projects" && i+1 < len(parts) {
				if logger != nil {
					logger.Logf("DEBUG: Found 'projects' at index %d, next part is: %s", i, parts[i+1])
				}
				return parts[i+1]
			}
		}

		if logger != nil {
			logger.Logf("DEBUG: Could not find 'projects' followed by project ID")
		}
	} else if logger != nil {
		logger.Logf("DEBUG: Subject does not contain 'projects/'")
	}

	// Check for 'accounts/' pattern
	accountTypes := []string{"accounts", "service-accounts", "serviceAccounts"}
	for _, accType := range accountTypes {
		searchTerm := accType + "/"
		if strings.Contains(sub, searchTerm) {
			if logger != nil {
				logger.Logf("DEBUG: Subject contains '%s'", searchTerm)
			}

			parts := strings.Split(sub, "/")
			if logger != nil {
				logger.Logf("DEBUG: Subject parts: %v", parts)
			}

			for i, part := range parts {
				if part == accType && i+1 < len(parts) {
					if logger != nil {
						logger.Logf("DEBUG: Found '%s' at index %d, next part is: %s", accType, i, parts[i+1])
					}
					return parts[i+1]
				}
			}

			if logger != nil {
				logger.Logf("DEBUG: Could not find '%s' followed by project ID", accType)
			}
		} else if logger != nil {
			logger.Logf("DEBUG: Subject does not contain '%s'", searchTerm)
		}
	}

	// Check for numeric-only project IDs
	// Project numbers in GCP are typically large numbers
	if logger != nil {
		logger.Logf("DEBUG: Checking for numeric project IDs")
	}

	for _, part := range strings.Split(sub, "/") {
		// If we find a part that looks like a project number (all digits, at least 6 digits)
		if len(part) >= 6 && isAllDigits(part) {
			if logger != nil {
				logger.Logf("DEBUG: Found numeric project ID candidate: %s", part)
			}
			return part
		}
	}

	if logger != nil {
		logger.Logf("DEBUG: Could not extract project ID from subject")
	}
	return ""
}

// isAllDigits checks if a string contains only digits
func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0 // Make sure it's not empty
}
