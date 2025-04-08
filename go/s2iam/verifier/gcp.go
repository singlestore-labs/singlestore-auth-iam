package verifier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/api/idtoken"
)

// hasGCPHeaders checks if the request has GCP authentication headers
func hasGCPHeaders(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	return strings.HasPrefix(authHeader, "Bearer ") && !hasAzureMarkers(r)
}

// verifyGCPRequest validates GCP credentials and returns the identity
func (v *Verifier) verifyGCPRequest(ctx context.Context, r *http.Request) (*CloudIdentity, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("invalid GCP authentication header format")
	}

	// Extract the token from the Authorization header
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return nil, errors.New("empty GCP token")
	}

	// Find a matching audience
	var validationErr error

	for _, audience := range v.config.AllowedAudiences {
		payload, err := v.gcpValidator.Validate(ctx, token, audience)
		if err == nil {
			// Extract the identity information from the token payload
			projectID, instanceID, serviceAccount, zone, err := extractGCPIdentifiers(payload)
			if err != nil {
				return nil, err
			}

			// Construct a more detailed identifier
			identifier := fmt.Sprintf("projects/%s/instances/%s", projectID, instanceID)
			if serviceAccount != "" {
				identifier += "/serviceAccounts/" + serviceAccount
			}

			resourceType := "instance"
			if strings.Contains(serviceAccount, "cloud-function") {
				resourceType = "function"
			} else if strings.Contains(serviceAccount, "app-engine") {
				resourceType = "appengine"
			}

			region := ""
			if zone != "" {
				// Extract region from zone (e.g., us-central1-a -> us-central1)
				parts := strings.Split(zone, "-")
				if len(parts) >= 3 {
					region = strings.Join(parts[:len(parts)-1], "-")
				}
			}

			// Prepare additional claims
			additionalClaims := make(map[string]string)
			for k, v := range payload.Claims {
				if str, ok := v.(string); ok {
					additionalClaims[k] = str
				}
			}

			return &CloudIdentity{
				Provider:         ProviderGCP,
				Identifier:       identifier,
				AccountID:        projectID,
				Region:           region,
				ResourceType:     resourceType,
				AdditionalClaims: additionalClaims,
			}, nil
		}
		validationErr = err
	}

	return nil, fmt.Errorf("invalid GCP token for allowed audiences: %w", validationErr)
}

// extractGCPIdentifiers extracts project and instance identifiers from the token payload
func extractGCPIdentifiers(payload *idtoken.Payload) (projectID, instanceID, serviceAccount, zone string, err error) {
	// Extract the project number
	if val, ok := payload.Claims["google/compute_engine/project_number"].(string); ok {
		projectID = val
	} else if val, ok := payload.Claims["project_id"].(string); ok {
		projectID = val
	} else {
		return "", "", "", "", errors.New("project identifier not found in GCP token")
	}

	// Extract the instance ID
	if val, ok := payload.Claims["google/compute_engine/instance_id"].(string); ok {
		instanceID = val
	} else {
		// For non-GCE resources, generate a placeholder
		instanceID = "non-gce-resource"
	}

	// Extract service account email
	if val, ok := payload.Claims["email"].(string); ok {
		serviceAccount = val
	}

	// Extract zone if present
	if val, ok := payload.Claims["google/compute_engine/zone"].(string); ok {
		zone = val
	}

	return projectID, instanceID, serviceAccount, zone, nil
}
