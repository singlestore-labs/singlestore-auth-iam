package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_Health(t *testing.T) {
	// Create server with a valid key size
	config := Config{
		Port:    8080,
		KeySize: 2048, // Set a valid key size
	}

	srv, err := NewServer(config)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	srv.handleHealth(w, req)

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var respData map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&respData)
	require.NoError(t, err)

	assert.Equal(t, "healthy", respData["status"])
	assert.NotNil(t, respData["time"])
}

func TestServer_PublicKey(t *testing.T) {
	// Create server with a valid key size
	config := Config{
		Port:    8080,
		KeySize: 2048, // Set a valid key size
	}

	srv, err := NewServer(config)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/info/public-key", nil)
	w := httptest.NewRecorder()

	srv.handlePublicKey(w, req)

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))

	// Now that the server returns PEM format, this check should pass
	pemData := w.Body.String()
	assert.True(t, strings.Contains(pemData, "BEGIN RSA PUBLIC KEY"), "Response should contain PEM header")
	assert.True(t, strings.Contains(pemData, "END RSA PUBLIC KEY"), "Response should contain PEM footer")

	// Parse the PEM data to ensure it's valid
	block, _ := pem.Decode([]byte(pemData))
	assert.NotNil(t, block, "Should be able to decode the PEM block")
	assert.Equal(t, "RSA PUBLIC KEY", block.Type)

	// Verify we can parse the key
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	assert.NoError(t, err, "Should be able to parse the public key")
	assert.NotNil(t, pubKey)
}

func TestServer_Auth_ErrorScenarios(t *testing.T) {
	testCases := []struct {
		name           string
		config         Config
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "return_error",
			config: Config{
				KeySize:      2048, // Set a valid key size
				ReturnError:  true,
				ErrorCode:    403,
				ErrorMessage: "Access Denied",
			},
			expectedStatus: 403,
			expectedBody:   "Access Denied",
		},
		{
			name: "fail_verification",
			config: Config{
				KeySize:          2048, // Set a valid key size
				FailVerification: true,
			},
			expectedStatus: 401,
			expectedBody:   "verification failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := NewServer(tc.config)
			require.NoError(t, err)

			req := httptest.NewRequest("GET", "/auth/iam/database", nil)
			w := httptest.NewRecorder()

			srv.handleAuth(w, req)

			resp := w.Result()
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
			assert.Contains(t, w.Body.String(), tc.expectedBody)
		})
	}
}

func TestServer_NewServer(t *testing.T) {
	config := Config{
		Port:             8080,
		KeySize:          2048,
		AllowedAudiences: []string{"audience1", "audience2"},
		AzureTenant:      "tenant-id",
	}

	srv, err := NewServer(config)
	require.NoError(t, err)

	assert.NotNil(t, srv.privateKey)
	assert.NotNil(t, srv.publicKey)
	assert.NotNil(t, srv.verifiers)
	assert.Equal(t, 0, len(srv.requestLog))
	assert.Equal(t, config, srv.config)
}

func TestParseFlags(t *testing.T) {
	// Test default values
	// Note: This doesn't actually parse command line args, just verifies the function structure
	config := parseFlags()

	assert.Equal(t, 8080, config.Port)
	assert.Equal(t, 2048, config.KeySize)
	assert.Equal(t, []string{"https://auth.singlestore.com"}, config.AllowedAudiences)
	assert.Equal(t, time.Hour, config.TokenExpiry)
	assert.Equal(t, "common", config.AzureTenant)
	assert.False(t, config.ReturnError)
	assert.False(t, config.ReturnEmptyJWT)
	assert.False(t, config.FailVerification)
}

// TestHandlePublicKey_PEM tests the handlePublicKey function but expects PEM format
// This test should be added once the server is updated to output PEM format
func TestHandlePublicKey_PEM(t *testing.T) {
	t.Skip("Server does not yet output keys in PEM format")

	// Create server with a valid key size
	config := Config{
		Port:    8080,
		KeySize: 2048,
	}

	srv, err := NewServer(config)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/info/public-key", nil)
	w := httptest.NewRecorder()

	srv.handlePublicKey(w, req)

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))

	// When the server supports PEM format, this check would work
	assert.True(t, strings.Contains(w.Body.String(), "BEGIN PUBLIC KEY"))
}

func TestServer_KeyPairMatches(t *testing.T) {
	// Create server with a valid key size
	config := Config{
		Port:    8080,
		KeySize: 2048,
	}

	srv, err := NewServer(config)
	require.NoError(t, err)

	// Get the public key via the HTTP endpoint
	req := httptest.NewRequest("GET", "/info/public-key", nil)
	w := httptest.NewRecorder()
	srv.handlePublicKey(w, req)

	// Parse the PEM data
	pemData := w.Body.Bytes()
	block, _ := pem.Decode(pemData)
	require.NotNil(t, block, "Should be able to decode the PEM block")

	// Parse the public key
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	require.NoError(t, err, "Should be able to parse the public key")

	// Generate a test message
	testMessage := []byte("test message for encryption")

	// Encrypt with the public key
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, testMessage)
	require.NoError(t, err, "Should be able to encrypt with the public key")

	// Decrypt with the server's private key
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, srv.privateKey, ciphertext)
	require.NoError(t, err, "Should be able to decrypt with the private key")

	// Verify the decrypted message matches the original
	assert.Equal(t, testMessage, plaintext, "Decrypted text should match original")
}

func TestServer_JWTVerification(t *testing.T) {
	// Create server with a valid key size
	config := Config{
		Port:        8080,
		KeySize:     2048,
		TokenExpiry: 5 * time.Minute,
	}

	srv, err := NewServer(config)
	require.NoError(t, err)

	// Create a sample identity
	identity := &models.CloudIdentity{
		Provider:   models.ProviderAWS,
		Identifier: "test:role/TestRole",
		AccountID:  "123456789012",
		Region:     "us-east-1",
	}

	// Create a JWT
	jwtToken, err := srv.createJWT(identity, "database")
	require.NoError(t, err, "Should be able to create a JWT")

	// Get the public key
	req := httptest.NewRequest("GET", "/info/public-key", nil)
	w := httptest.NewRecorder()
	srv.handlePublicKey(w, req)

	// Parse the PEM data
	pemData := w.Body.Bytes()
	block, _ := pem.Decode(pemData)
	require.NotNil(t, block, "Should be able to decode the PEM block")

	// Parse the public key
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	require.NoError(t, err, "Should be able to parse the public key")

	// Parse and verify the JWT
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})

	require.NoError(t, err, "Should be able to verify the JWT")
	assert.True(t, token.Valid, "JWT should be valid")

	// Verify claims
	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok, "Should be able to extract claims")
	assert.Equal(t, identity.Identifier, claims["sub"])
	assert.Equal(t, "aws", claims["provider"])
	assert.Equal(t, identity.AccountID, claims["accountID"])
	assert.Equal(t, identity.Region, claims["region"])
	assert.Equal(t, "database", claims["jwtType"])
}

func TestServer_RandomPort(t *testing.T) {
	// Create server with port 0 for random port
	config := Config{
		Port:    0, // Use port 0 for random port
		KeySize: 2048,
	}

	srv, err := NewServer(config)
	require.NoError(t, err)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Set up a context with cancellation for clean shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in a goroutine
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- srv.Run(ctx)
	}()

	// Read the output to get server info
	// Since the server now waits until it's ready before printing JSON,
	// we can parse immediately without additional waiting
	decoder := json.NewDecoder(r)

	// Read until we get the JSON object
	var serverInfoWrapper struct {
		ServerInfo struct {
			Port      int               `json:"port"`
			Endpoints map[string]string `json:"endpoints"`
		} `json:"server_info"`
	}

	err = decoder.Decode(&serverInfoWrapper)
	require.NoError(t, err, "Should be able to decode server info")

	// Restore stdout
	_ = w.Close()
	os.Stdout = oldStdout

	port := serverInfoWrapper.ServerInfo.Port
	endpoints := serverInfoWrapper.ServerInfo.Endpoints

	// Verify the port
	require.Greater(t, port, 0, "Server should be assigned a non-zero port")

	// Check that this matches the GetPort method
	assert.Equal(t, port, srv.GetPort(), "GetPort() should return the same port")

	// The server is guaranteed to be ready when it prints JSON,
	// so we can immediately make a request
	healthURL := endpoints["health"]
	resp, err := http.Get(healthURL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Clean up resources properly
	cancel() // Cancel the context to trigger server shutdown

	// Wait for server to finish with a timeout
	select {
	case err := <-serverDone:
		// Server exited cleanly or with expected error from context cancellation
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Server exited with unexpected error: %+v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for server to shut down")
	}
}
