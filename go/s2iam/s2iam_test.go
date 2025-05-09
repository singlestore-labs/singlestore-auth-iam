package s2iam_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"
)

var privateKey, publicKey = func() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key pair: %v", err)
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey
}()

func validateJWT(t *testing.T, tokenString string) jwt.MapClaims {
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	require.NoError(t, err)
	require.True(t, parsedToken.Valid)
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims
}

func signJWT(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	return tokenString, err
}

type fakeServerFlags struct{}

/*
func startFakeServer(t *testing.T, flags fakeServerFlags) *httptest.Server {
	v, err := s2iam.CreateVerifiers(context.Background(),
		s2iam.VerifierConfig{
			Logger: t, // Directly use testing.T as the logger
			AllowedAudiences: []string{
				"https://auth.singlestore.com",
				"https://auth.singlestore.com/auth/iam/database",
				"https://auth.singlestore.com/auth/iam/api",
				// Add some more common values as fallbacks
				"*",
				"",
				"https://localhost",
			},
})
	require.NoError(t, err)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("[server] received request %s %s", r.Method, r.URL)
		t.Log("[server] verifying service account")
		cloudIdentity, err := v.VerifyRequest(r.Context(), r)
		if err != nil {
			t.Logf("[server] verification failed: %s", err)
			http.Error(w, err.Error(), 400)
			return
		}
		t.Logf("[server] service account verified: %s %s", cloudIdentity.Provider, cloudIdentity.Identifier)
		tokenString, err := signJWT(jwt.MapClaims{
			"sub":          cloudIdentity.Identifier,
			"provider":     cloudIdentity.Provider,
			"accountID":    cloudIdentity.AccountID,
			"region":       cloudIdentity.Region,
			"resourceType": cloudIdentity.ResourceType,
			"iat":          time.Now().Unix(),
			"exp":          time.Now().Add(time.Hour).Unix(),
		})
		if err != nil {
			t.Logf("[server] jwt creation failed: %s", err)
			http.Error(w, err.Error(), 500)
			return
		}
		enc, err := json.Marshal(map[string]any{
			"jwt": tokenString,
		})
		if err != nil {
			t.Logf("[server] jwt creation failed: %s", err)
			http.Error(w, err.Error(), 500)
			return
		}
		_, _ = w.Write(enc)
		t.Log("[server] returning jwt")
		return
	}))
	t.Cleanup(s.Close)
	return s
}

XXX
*/

func TestGetDatabaseTestServerJWT(t *testing.T) {
	client, err := s2iam.DetectProvider(context.Background(),
		s2iam.WithLogger(t),
		s2iam.WithTimeout(time.Second*5))
	if err != nil {
		t.Skipf("test requires a cloud provider: %+v", err)
	}
	t.Logf("[client] making request from %s client", client.GetType())
	fakeServer := startFakeServer(t, fakeServerFlags{})
	ctx := context.Background()
	jwt, err := s2iam.GetDatabaseJWT(ctx, "fake-workspace", s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"))
	require.NoError(t, err)
	require.NotEmpty(t, jwt)
	t.Log("[client] verifying jwt")
	validateJWT(t, jwt)
}

func startFakeServer(t *testing.T, flags fakeServerFlags) *httptest.Server {
	// Create verifiers with enhanced logging
	v, err := s2iam.CreateVerifiers(context.Background(),
		s2iam.VerifierConfig{
			Logger: t,
			// Set allowed audiences for GCP verification
			AllowedAudiences: []string{
				"https://auth.singlestore.com",
				"https://auth.singlestore.com/auth/iam/database",
				"https://auth.singlestore.com/auth/iam/api",
				// Add some more common values as fallbacks
				"*",
				"",
				"https://localhost",
			},
		})
	require.NoError(t, err)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("[server] received request %s %s", r.Method, r.URL)
		t.Log("[server] verifying service account")

		// Log all headers to see what we're receiving
		t.Log("[server] Request headers:")
		for name, values := range r.Header {
			t.Logf("[server]   %s: %v", name, values)
		}

		// Attempt to parse authorization token directly for test visibility
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			t.Logf("[server] Examining token: %s", token[:min(len(token), 20)]+"...")

			// Try to parse the token without validation to see its contents
			parts := strings.Split(token, ".")
			if len(parts) == 3 {
				// Decode the payload (middle part)
				payload, err := base64.RawURLEncoding.DecodeString(parts[1])
				if err == nil {
					t.Logf("[server] Decoded token payload: %s", string(payload))
				}
			}

			parsedToken, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
				return nil, nil // We're just examining, not validating
			})

			if parsedToken != nil {
				if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
					t.Log("[server] Token claims:")
					for key, value := range claims {
						t.Logf("[server]   %s: %v (type: %T)", key, value, value)
					}
				}
			}
		}

		// Try to manually call HasHeaders to see if it detects GCP headers
		t.Logf("[server] Testing GCP HeaderCheck: %v", v["gcp"].HasHeaders(r))
		t.Logf("[server] Testing AWS HeaderCheck: %v", v["aws"].HasHeaders(r))
		t.Logf("[server] Testing Azure HeaderCheck: %v", v["azure"].HasHeaders(r))

		// Proceed with normal verification
		cloudIdentity, err := v.VerifyRequest(r.Context(), r)
		if err != nil {
			t.Logf("[server] verification failed: %s", err)
			http.Error(w, err.Error(), 400)
			return
		}

		t.Logf("[server] service account verified: %s %s", cloudIdentity.Provider, cloudIdentity.Identifier)
		tokenString, err := signJWT(jwt.MapClaims{
			"sub":          cloudIdentity.Identifier,
			"provider":     cloudIdentity.Provider,
			"accountID":    cloudIdentity.AccountID,
			"region":       cloudIdentity.Region,
			"resourceType": cloudIdentity.ResourceType,
			"iat":          time.Now().Unix(),
			"exp":          time.Now().Add(time.Hour).Unix(),
		})
		if err != nil {
			t.Logf("[server] jwt creation failed: %s", err)
			http.Error(w, err.Error(), 500)
			return
		}
		enc, err := json.Marshal(map[string]any{
			"jwt": tokenString,
		})
		if err != nil {
			t.Logf("[server] jwt creation failed: %s", err)
			http.Error(w, err.Error(), 500)
			return
		}
		_, _ = w.Write(enc)
		t.Log("[server] returning jwt")
		return
	}))
	t.Cleanup(s.Close)
	return s
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
