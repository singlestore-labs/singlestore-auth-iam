package s2iam_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
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

func startFakeServer(t *testing.T, flags fakeServerFlags) *httptest.Server {
	v, err := s2iam.CreateVerifiers(context.Background(),
		s2iam.VerifierConfig{})
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

func TestGetDatabaseTestServerJWT(t *testing.T) {
	client, err := s2iam.DetectProvider(context.Background(), time.Second*5)
	if err != nil {
		t.Skipf("test requires a cloud provider: %+v", err)
	}
	t.Logf("[client] makeing request from %s client", client.GetType())
	fakeServer := startFakeServer(t, fakeServerFlags{})
	ctx := context.Background()
	jwt, err := s2iam.GetDatabaseJWT(ctx, "fake-workspace", s2iam.WithServerURL(fakeServer.URL+"/iam/:jwtType"))
	require.NoError(t, err)
	require.NotEmpty(t, jwt)
	t.Log("[client] verifying jwt")
	validateJWT(t, jwt)
}
