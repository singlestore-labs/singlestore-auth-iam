package verifier

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// Azure OIDC well-known configuration
	azureOIDCConfigFmt = "https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration"
	defaultAzureTenant = "common"
)

// hasAzureHeaders checks if the request has Azure authentication headers
func hasAzureHeaders(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	return strings.HasPrefix(authHeader, "Bearer ") && hasAzureMarkers(r)
}

// hasAzureMarkers checks for Azure-specific traits in the token
// This helps disambiguate between GCP and Azure tokens which both use Bearer auth
func hasAzureMarkers(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Perform a quick check without fully parsing the token
	// Azure tokens typically have these characteristics
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

// verifyAzureRequest validates Azure credentials and returns the identity
func (v *Verifier) verifyAzureRequest(ctx context.Context, r *http.Request) (*CloudIdentity, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("invalid Azure authentication header format")
	}

	// Extract the token from the Authorization header
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		return nil, errors.New("empty Azure token")
	}

	// Parse without verifying to extract claims first
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return nil, nil // We're not validating yet
	})

	// Extract claims even if validation failed
	var claims jwt.MapClaims
	if token != nil {
		if parsedClaims, ok := token.Claims.(jwt.MapClaims); ok {
			claims = parsedClaims
		}
	}

	if claims == nil {
		return nil, errors.New("failed to parse Azure token claims")
	}

	// Get token issuer to determine tenant
	var issuer string
	if iss, ok := claims["iss"].(string); ok {
		issuer = iss
	} else {
		return nil, errors.New("issuer claim missing from token")
	}

	// Check that it's an Azure token
	if !strings.Contains(issuer, "microsoftonline.com") && !strings.Contains(issuer, "windows.net") {
		return nil, errors.New("token not issued by Azure AD")
	}

	// Extract the kid (key ID) from the token header
	var kid string
	if token.Header["kid"] != nil {
		kid = token.Header["kid"].(string)
	} else {
		return nil, errors.New("kid header missing from token")
	}

	// Get the appropriate key from JWKS
	key, err := v.azureJWKSMgr.getKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure signing key: %w", err)
	}

	// Parse and validate the JWT token with the correct key
	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the algorithm
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("Azure token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("Azure token is invalid")
	}

	// Get updated claims from validated token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("could not parse Azure token claims")
	}

	// Verify audience claim against allowed audiences
	audience, _ := claims["aud"].(string)
	audienceValid := false

	for _, allowedAudience := range v.config.AllowedAudiences {
		if audience == allowedAudience || audience == "https://management.azure.com/" {
			audienceValid = true
			break
		}
	}

	if !audienceValid {
		return nil, errors.New("Azure token has invalid audience")
	}

	// Extract the principal ID
	principalID, err := extractAzurePrincipalID(claims)
	if err != nil {
		return nil, err
	}

	// Extract additional information
	tenantID, _ := extractTenantFromIssuer(issuer)
	// subscriptionID, _ := claims["xms_mirid"].(string)
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

	return &CloudIdentity{
		Provider:         ProviderAzure,
		Identifier:       principalID,
		AccountID:        tenantID,
		Region:           region,
		ResourceType:     resourceType,
		AdditionalClaims: additionalClaims,
	}, nil
}

// extractTenantFromIssuer extracts the tenant ID from the issuer URL
func extractTenantFromIssuer(issuer string) (string, error) {
	parts := strings.Split(issuer, "/")
	for i, part := range parts {
		if part == "tokens" && i > 0 {
			return parts[i-1], nil
		}
	}
	return "", errors.New("tenant ID not found in issuer URL")
}

// extractAzurePrincipalID extracts the principal ID from the token claims
func extractAzurePrincipalID(claims jwt.MapClaims) (string, error) {
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

	return "", errors.New("principal ID not found in Azure token")
}
