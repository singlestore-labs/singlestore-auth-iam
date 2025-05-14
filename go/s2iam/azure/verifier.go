package azure

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/memsql/errors"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
)

const (
	// Azure OIDC well-known configuration
	defaultAzureTenant = "common"
)

// AzureVerifier implements the CloudProviderVerifier interface for Azure
type AzureVerifier struct {
	allowedAudiences []string
	tenant           string
	logger           models.Logger
	jwksManager      *jwksManager
}

// NewVerifier creates or configures the Azure verifier
func NewVerifier(allowedAudiences []string, tenant string, logger models.Logger) models.CloudProviderVerifier {
	if tenant == "" {
		tenant = defaultAzureTenant // Use the common endpoint by default
	}
	return &AzureVerifier{
		allowedAudiences: allowedAudiences,
		tenant:           tenant,
		logger:           logger,
		jwksManager:      getJWKSManager(tenant),
	}
}

// HasHeaders returns true if the request has Azure authentication headers
func (v *AzureVerifier) HasHeaders(r *http.Request) bool {
	return HasAzureMarkers(r)
}

// HasAzureMarkers checks for Azure-specific traits in the token. This is exported
// for other verifiers to use for elimination.
func HasAzureMarkers(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Perform a quick check without fully parsing the token
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	// Try to decode the payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	// Look for Azure-specific claims without fully parsing JSON
	return strings.Contains(string(payload), "microsoftonline.com") ||
		strings.Contains(string(payload), "windows.net")
}

// VerifyRequest validates Azure credentials and returns the identity
func (v *AzureVerifier) VerifyRequest(ctx context.Context, r *http.Request) (*models.CloudIdentity, error) {
	logger := v.logger

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Continue normally
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		if logger != nil {
			logger.Logf("Invalid Azure authentication header format")
		}
		return nil, errors.Errorf("invalid Azure authentication header format")
	}

	// Extract the token from the Authorization header
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		if logger != nil {
			logger.Logf("Empty Azure token")
		}
		return nil, errors.Errorf("empty Azure token")
	}

	// Parse without verifying to extract kid from header
	unverifiedToken, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		if logger != nil {
			logger.Logf("Failed to parse Azure token for header extraction: %v", err)
		}
		return nil, errors.Errorf("failed to parse Azure token: %w", err)
	}

	// Extract kid from token header
	kid, ok := unverifiedToken.Header["kid"].(string)
	if !ok || kid == "" {
		if logger != nil {
			logger.Logf("Missing kid header in Azure token")
		}
		return nil, errors.Errorf("missing kid header in Azure token")
	}

	// Get the key for this kid
	key, err := v.jwksManager.getKey(ctx, kid)
	if err != nil {
		if logger != nil {
			logger.Logf("Failed to get Azure signing key: %v", err)
		}
		return nil, errors.Errorf("failed to get Azure signing key: %w", err)
	}

	// Create a custom key function that returns our cached key
	keyFunc := func(token *jwt.Token) (any, error) {
		return key, nil
	}

	// Parse and validate the token using the jwt package, all all known public key, but no private key methods
	token, err := jwt.Parse(tokenString, keyFunc, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}))
	if err != nil {
		if logger != nil {
			logger.Logf("Failed to parse/validate Azure token with %T key: %v", key, err)
		}
		return nil, errors.Errorf("failed to parse/validate Azure token: %w", err)
	}

	if !token.Valid {
		if logger != nil {
			logger.Logf("Azure token is invalid")
		}
		return nil, errors.Errorf("Azure token is invalid")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		if logger != nil {
			logger.Logf("Failed to extract claims from Azure token")
		}
		return nil, errors.Errorf("failed to extract claims from Azure token")
	}

	// Validate audience
	audience, ok := claims["aud"].(string)
	if !ok {
		if logger != nil {
			logger.Logf("Missing audience claim")
		}
		return nil, errors.Errorf("missing audience claim in token")
	}

	audienceValid := false
	for _, allowedAudience := range v.allowedAudiences {
		if audience == allowedAudience || audience == "https://management.azure.com/" {
			audienceValid = true
			break
		}
	}

	if !audienceValid {
		if logger != nil {
			logger.Logf("Azure token has invalid audience: %s", audience)
		}
		return nil, errors.Errorf("Azure token has invalid audience: %s", audience)
	}

	// Get token issuer to determine tenant
	var issuer string
	if iss, ok := claims["iss"].(string); ok {
		issuer = iss
	} else {
		if logger != nil {
			logger.Logf("Issuer claim missing from token")
		}
		return nil, errors.Errorf("issuer claim missing from token")
	}

	// Check that it's an Azure token
	if !strings.Contains(issuer, "microsoftonline.com") && !strings.Contains(issuer, "windows.net") {
		if logger != nil {
			logger.Logf("Token not issued by Azure AD")
		}
		return nil, errors.Errorf("token not issued by Azure AD")
	}

	if logger != nil {
		logger.Logf("Verifying Azure token from issuer: %s", issuer)
	}

	// Extract the principal ID
	principalID, err := extractPrincipalID(claims)
	if err != nil {
		if logger != nil {
			logger.Logf("Failed to extract principal ID: %v", err)
		}
		return nil, errors.Errorf("failed to extract principal ID: %w", err)
	}

	// Extract additional information
	tenantID, _ := extractTenantFromIssuer(issuer)
	resourceType := "unknown"
	region := ""

	// Extract resource type and region from the token
	if mirid, ok := claims["xms_mirid"].(string); ok {
		parts := strings.Split(mirid, "/")
		if len(parts) > 2 {
			for i := 0; i < len(parts)-1; i++ {
				if parts[i] == "resourceGroups" && i+1 < len(parts) {
					// Extract region from resource group if possible
					rgParts := strings.Split(parts[i+1], "-")
					if len(rgParts) > 2 {
						region = rgParts[len(rgParts)-2] + "-" + rgParts[len(rgParts)-1]
					}
				}
				if parts[i] == "providers" && i+1 < len(parts) {
					resourceType = parts[i+1]
				}
			}
		}
	}

	// Prepare additional claims
	additionalClaims := make(map[string]string)
	for k, v := range claims {
		if str, ok := v.(string); ok {
			additionalClaims[k] = str
		}
	}

	if logger != nil {
		logger.Logf("Successfully verified Azure identity: %s", principalID)
	}

	return &models.CloudIdentity{
		Provider:         models.ProviderAzure,
		Identifier:       principalID,
		AccountID:        tenantID,
		Region:           region,
		ResourceType:     resourceType,
		AdditionalClaims: additionalClaims,
	}, nil
}

// extractPrincipalID extracts the principal ID from the token claims
func extractPrincipalID(claims jwt.MapClaims) (string, error) {
	// Primary location: objectId/oid claim contains the principal ID
	if principalID, ok := claims["oid"].(string); ok {
		return principalID, nil
	}

	// Alternative location: subject claim may contain the principal ID
	if sub, ok := claims["sub"].(string); ok {
		return sub, nil
	}

	// Last resort: check appid
	if appID, ok := claims["appid"].(string); ok {
		return appID, nil
	}

	return "", errors.Errorf("principal ID not found in Azure token")
}

// extractTenantFromIssuer extracts the tenant ID from the issuer URL
func extractTenantFromIssuer(issuer string) (string, error) {
	parts := strings.Split(issuer, "/")
	for i, part := range parts {
		if part == "tokens" && i > 0 {
			return parts[i-1], nil
		}
	}
	return "", errors.Errorf("tenant ID not found in issuer URL")
}
