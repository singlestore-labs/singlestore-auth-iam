package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/models"
	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam/s2verifier"
)

// Config holds the test server configuration
type Config struct {
	Port             int
	KeySize          int
	FailVerification bool
	ReturnEmptyJWT   bool
	ReturnError      bool
	ErrorCode        int
	ErrorMessage     string
	RequiredAudience string
	AzureTenant      string
	TokenExpiry      time.Duration
	AllowedAudiences []string
	Verbose          bool
}

// Server holds the test server state
type Server struct {
	config     Config
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	verifiers  s2verifier.Verifiers
	requestLog []RequestInfo
}

// RequestInfo captures details about incoming requests
type RequestInfo struct {
	Time       time.Time
	Method     string
	Path       string
	Provider   string
	Identifier string
	AccountID  string
	Region     string
	JWTType    string
	Headers    map[string]string
}

func main() {
	config := parseFlags()

	srv, err := NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func parseFlags() Config {
	config := Config{
		AllowedAudiences: make([]string, 0), // Initialize as empty slice
	}

	var allowedAudiencesStr string // Use a temporary string variable

	flag.IntVar(&config.Port, "port", 8080, "Port to listen on")
	flag.IntVar(&config.KeySize, "key-size", 2048, "RSA key size")
	flag.BoolVar(&config.FailVerification, "fail-verification", false, "Fail verification for all requests")
	flag.BoolVar(&config.ReturnEmptyJWT, "return-empty-jwt", false, "Return empty JWT in response")
	flag.BoolVar(&config.ReturnError, "return-error", false, "Return an error response")
	flag.IntVar(&config.ErrorCode, "error-code", 500, "HTTP error code to return (when --return-error)")
	flag.StringVar(&config.ErrorMessage, "error-message", "Internal Server Error", "Error message to return")
	flag.StringVar(&config.RequiredAudience, "required-audience", "", "Required audience value for GCP tokens")
	flag.StringVar(&config.AzureTenant, "azure-tenant", "common", "Azure tenant ID")
	flag.DurationVar(&config.TokenExpiry, "token-expiry", time.Hour, "Token expiry duration")
	flag.StringVar(&allowedAudiencesStr, "allowed-audiences", "https://auth.singlestore.com", "Comma-separated list of allowed audiences")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")

	flag.Parse()

	// Parse allowed audiences
	if allowedAudiencesStr != "" {
		config.AllowedAudiences = strings.Split(allowedAudiencesStr, ",")
	}

	return config
}

// NewServer creates a new test server
func NewServer(config Config) (*Server, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("error generating RSA key: %w", err)
	}

	// Create verifiers
	verifierConfig := s2verifier.VerifierConfig{
		AllowedAudiences: config.AllowedAudiences,
		AzureTenant:      config.AzureTenant,
	}

	if config.Verbose {
		verifierConfig.Logger = logger{}
	}

	verifiers, err := s2verifier.CreateVerifiers(context.Background(), verifierConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating verifiers: %w", err)
	}

	return &Server{
		config:     config,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		verifiers:  verifiers,
		requestLog: make([]RequestInfo, 0),
	}, nil
}

type logger struct{}

func (_ logger) Logf(format string, args ...any) {
	log.Printf("[verifier] "+format, args...)
}

// Run starts the test server
func (s *Server) Run() error {
	mux := http.NewServeMux()

	// Auth endpoints
	mux.HandleFunc("/auth/iam/", s.handleAuth)

	// Info endpoints
	mux.HandleFunc("/info/public-key", s.handlePublicKey)
	mux.HandleFunc("/info/requests", s.handleRequestLog)
	mux.HandleFunc("/health", s.handleHealth)

	addr := fmt.Sprintf(":%d", s.config.Port)
	log.Printf("Starting S2IAM test server on %s", addr)

	// Start listening on all interfaces (needed for Docker/cross-language testing)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	log.Printf("Server started. Endpoints:")
	log.Printf("  Auth:       http://localhost:%d/auth/iam/:jwtType", s.config.Port)
	log.Printf("  Public Key: http://localhost:%d/info/public-key", s.config.Port)
	log.Printf("  Requests:   http://localhost:%d/info/requests", s.config.Port)
	log.Printf("  Health:     http://localhost:%d/health", s.config.Port)

	return http.Serve(listener, mux)
}

// handleAuth handles authentication requests
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	// Extract JWT type from URL
	pathParts := strings.Split(r.URL.Path, "/")
	jwtType := ""
	if len(pathParts) >= 4 {
		jwtType = pathParts[len(pathParts)-1]
	}

	// Log request details
	reqInfo := RequestInfo{
		Time:    time.Now(),
		Method:  r.Method,
		Path:    r.URL.Path,
		JWTType: jwtType,
		Headers: make(map[string]string),
	}

	// Capture key headers
	for key, values := range r.Header {
		if len(values) > 0 {
			reqInfo.Headers[key] = values[0]
		}
	}

	if s.config.Verbose {
		log.Printf("Received request: %s %s", r.Method, r.URL.Path)
		for key, value := range reqInfo.Headers {
			log.Printf("  Header: %s: %s", key, value)
		}
	}

	// Simulate various error conditions
	if s.config.ReturnError {
		http.Error(w, s.config.ErrorMessage, s.config.ErrorCode)
		return
	}

	if s.config.FailVerification {
		http.Error(w, "verification failed", http.StatusUnauthorized)
		return
	}

	// Verify the request
	identity, err := s.verifiers.VerifyRequest(r.Context(), r)
	if err != nil {
		if s.config.Verbose {
			log.Printf("Verification failed: %v", err)
		}
		http.Error(w, fmt.Sprintf("verification failed: %v", err), http.StatusBadRequest)
		return
	}

	// Update request info with identity
	reqInfo.Provider = string(identity.Provider)
	reqInfo.Identifier = identity.Identifier
	reqInfo.AccountID = identity.AccountID
	reqInfo.Region = identity.Region
	s.requestLog = append(s.requestLog, reqInfo)

	if s.config.Verbose {
		log.Printf("Verified identity: %s %s", identity.Provider, identity.Identifier)
	}

	// Return empty JWT if configured
	if s.config.ReturnEmptyJWT {
		response := map[string]string{"jwt": ""}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Create JWT
	tokenString, err := s.createJWT(identity, jwtType)
	if err != nil {
		http.Error(w, fmt.Sprintf("error creating JWT: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]string{"jwt": tokenString}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// createJWT generates a JWT for the given identity
func (s *Server) createJWT(identity *models.CloudIdentity, jwtType string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":          identity.Identifier,
		"provider":     identity.Provider,
		"accountID":    identity.AccountID,
		"region":       identity.Region,
		"resourceType": identity.ResourceType,
		"jwtType":      jwtType,
		"iat":          now.Unix(),
		"exp":          now.Add(s.config.TokenExpiry).Unix(),
	}

	// Add any additional properties
	for key, value := range identity.AdditionalClaims {
		claims[key] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

// handlePublicKey returns the server's public key
func (s *Server) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	// Export public key in PEM format
	publicKey := x509.MarshalPKCS1PublicKey(s.publicKey)

	// Convert to PEM format
	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKey,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	w.Header().Set("Content-Type", "text/plain")
	w.Write(pemData)
}

// handleRequestLog returns logged requests
func (s *Server) handleRequestLog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.requestLog)
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "healthy",
		"time":   time.Now(),
		"config": map[string]interface{}{
			"port":             s.config.Port,
			"failVerification": s.config.FailVerification,
			"returnEmptyJWT":   s.config.ReturnEmptyJWT,
			"returnError":      s.config.ReturnError,
		},
	})
}
