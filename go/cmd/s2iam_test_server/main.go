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
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	Timeout          time.Duration
	InfoFile         string // Path to atomically written server info
	ShutdownOnStdin  bool   // Graceful shutdown when stdin closes
}

// Standardized timeouts (avoid magic numbers)
const (
	serverShutdownTimeout   = 5 * time.Second
	serverClientTimeout     = 5 * time.Second
	serverProbeTotalTimeout = 5 * time.Second
	serverProbeInterval     = 100 * time.Millisecond
	serverProbeReqTimeout   = 500 * time.Millisecond
)

// Server holds the test server state
type Server struct {
	config     Config
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	verifiers  s2verifier.Verifiers
	requestLog []RequestInfo
	listener   net.Listener // Add a field to store the listener
}

// debugLog writes to a debug file if S2IAM_TEST_SERVER_DEBUG_LOG is set
func debugLog(format string, args ...interface{}) {
	if debugFile := os.Getenv("S2IAM_TEST_SERVER_DEBUG_LOG"); debugFile != "" {
		f, err := os.OpenFile(debugFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			defer func() {
				_ = f.Close()
			}()
			timestamp := time.Now().Format("2006-01-02 15:04:05.000")
			_, _ = fmt.Fprintf(f, "[%s] %s\n", timestamp, fmt.Sprintf(format, args...))
		}
	}
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
	Claims     map[string]interface{} `json:"claims,omitempty"`
	Identity   map[string]string      `json:"identity,omitempty"`
}

func main() {
	// Redirect all log output to stderr to keep stdout clean for JSON
	log.SetOutput(os.Stderr)

	config := parseFlags()

	srv, err := NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Run(context.Background()); err != nil {
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
	flag.StringVar(&allowedAudiencesStr, "allowed-audiences", "https://authsvc.singlestore.com", "Comma-separated list of allowed audiences")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flag.DurationVar(&config.Timeout, "timeout", 0, "Auto-shutdown timeout (0 = no timeout)")
	flag.StringVar(&config.InfoFile, "info-file", "", "Write server info JSON atomically to this file")
	flag.BoolVar(&config.ShutdownOnStdin, "shutdown-on-stdin-close", false, "Shutdown when stdin closes (for test cleanup)")

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

func (logger) Logf(format string, args ...any) {
	log.Printf("[verifier] "+format, args...)
}

// writeAtomic writes data to filename atomically via temp file + rename.
func writeAtomic(filename string, data []byte, perm os.FileMode) (err error) {
	if filename == "" {
		return fmt.Errorf("empty filename")
	}
	dir := filepath.Dir(filename)
	base := filepath.Base(filename)
	var tmp *os.File
	tmp, err = os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil { // only cleanup on failure
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return
	}
	// fsync omitted (tests only); atomic rename ensures visibility boundary
	if err = tmp.Close(); err != nil {
		return
	}
	if perm != 0 {
		if err = os.Chmod(tmpName, perm); err != nil {
			return
		}
	}
	err = os.Rename(tmpName, filename)
	return
}

// Run starts the test server
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()

	// Auth endpoints
	mux.HandleFunc("/auth/iam/", s.handleAuth)

	// Info endpoints
	mux.HandleFunc("/info/public-key", s.handlePublicKey)
	mux.HandleFunc("/info/requests", s.handleRequestLog)
	mux.HandleFunc("/health", s.handleHealth)

	// Use the configured port, or 0 to select a random available port
	port := s.config.Port
	addr := fmt.Sprintf(":%d", port)

	// Start listening on all interfaces using ListenConfig with context
	lc := net.ListenConfig{}
	var err error
	s.listener, err = lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// Get the actual port (especially important when using port 0)
	actualPort := s.listener.Addr().(*net.TCPAddr).Port

	// Log standard text message
	log.Printf("Starting S2IAM test server on port %d", actualPort)

	// Create HTTP server
	httpServer := &http.Server{
		Handler: mux,
	}

	// Start the server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- httpServer.Serve(s.listener)
	}()

	// Handle context cancellation and auto-shutdown timeout
	go func() {
		if s.config.Timeout > 0 {
			// Set up auto-shutdown timer
			timer := time.NewTimer(s.config.Timeout)
			defer timer.Stop()

			select {
			case <-ctx.Done():
				// Context cancelled before timeout
			case <-timer.C:
				// Timeout reached
				log.Printf("Auto-shutdown timeout (%v) reached, shutting down server...", s.config.Timeout)
			}
		} else {
			// No timeout, just wait for context cancellation
			<-ctx.Done()
		}

		log.Printf("Shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	// Wait for the server to be ready by checking the health endpoint
	client := &http.Client{Timeout: serverClientTimeout}
	healthURL := fmt.Sprintf("http://localhost:%d/health", actualPort)

	// Retry loop to ensure server is ready
	probeCtx, probeCancel := context.WithTimeout(ctx, serverProbeTotalTimeout)
	defer probeCancel()

	for {
		select {
		case err := <-serverErr:
			// Server failed to start
			return fmt.Errorf("server failed to start: %w", err)
		case <-probeCtx.Done():
			// Timeout waiting for server to be ready or context cancelled
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("timeout waiting for server to be ready")
		default:
			// Try to hit the health endpoint
			reqCtx, reqCancel := context.WithTimeout(probeCtx, serverProbeReqTimeout)
			req, _ := http.NewRequestWithContext(reqCtx, "GET", healthURL, nil)
			resp, err := client.Do(req)
			reqCancel()

			if err == nil && resp.StatusCode == http.StatusOK {
				_ = resp.Body.Close()
				// Server is ready, exit the loop
				goto ServerReady
			}
			if resp != nil {
				_ = resp.Body.Close()
			}

			// Wait before trying again
			time.Sleep(serverProbeInterval)
		}
	}
ServerReady:

	// Build server info
	serverInfo := map[string]interface{}{
		"server_info": map[string]interface{}{
			"port":       actualPort,
			"pid":        os.Getpid(),
			"started_at": time.Now().UTC().Format(time.RFC3339Nano),
			"endpoints": map[string]string{
				"auth":       fmt.Sprintf("http://localhost:%d/auth/iam/:jwtType", actualPort),
				"public_key": fmt.Sprintf("http://localhost:%d/info/public-key", actualPort),
				"requests":   fmt.Sprintf("http://localhost:%d/info/requests", actualPort),
				"health":     fmt.Sprintf("http://localhost:%d/health", actualPort),
			},
			"config": map[string]interface{}{
				"fail_verification": s.config.FailVerification,
				"return_empty_jwt":  s.config.ReturnEmptyJWT,
				"return_error":      s.config.ReturnError,
				"error_code":        s.config.ErrorCode,
				"token_expiry":      s.config.TokenExpiry.String(),
			},
		},
	}
	jsonInfo, err := json.MarshalIndent(serverInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal server info: %w", err)
	}
	if s.config.InfoFile == "" { // Only emit to stdout when no file requested
		fmt.Println(string(jsonInfo))
	} else {
		if err := writeAtomic(s.config.InfoFile, jsonInfo, 0o644); err != nil {
			return fmt.Errorf("write info file: %w", err)
		}
		log.Printf("info file written: %s", s.config.InfoFile)
	}
	// Optional stdin watcher
	if s.config.ShutdownOnStdin {
		// Consume all stdin until EOF (or read error) then trigger shutdown.
		// Using io.Copy with a large internal buffer avoids pathological byte-by-byte reads
		// if input is accidentally written to stdin.
		go func() {
			_, err := io.Copy(io.Discard, os.Stdin)
			if err != nil && err != io.EOF {
				log.Printf("stdin copy error: %v; shutting down", err)
			} else {
				log.Printf("stdin closed; shutting down")
			}
			ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer cancel()
			_ = httpServer.Shutdown(ctx)
		}()
	}

	// Wait for the server to complete (or error)
	return <-serverErr
}

// GetPort returns the actual port the server is listening on
func (s *Server) GetPort() int {
	if s.listener == nil {
		return 0
	}
	return s.listener.Addr().(*net.TCPAddr).Port
}

// handleAuth handles authentication requests
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	debugLog("===== GO TEST SERVER: Received auth request for %s =====", r.URL.Path)
	debugLog("===== GO TEST SERVER: Request method: %s =====", r.Method)

	// Extract JWT type from URL
	pathParts := strings.Split(r.URL.Path, "/")
	jwtType := ""
	if len(pathParts) >= 4 {
		jwtType = pathParts[len(pathParts)-1]
	}

	debugLog("===== GO TEST SERVER: JWT type: %s =====", jwtType)

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

	// Populate identity fields prior to JWT creation
	reqInfo.Provider = string(identity.Provider)
	reqInfo.Identifier = identity.Identifier
	reqInfo.AccountID = identity.AccountID
	reqInfo.Region = identity.Region

	if s.config.Verbose {
		log.Printf("Verified identity: %s %s", identity.Provider, identity.Identifier)
	}

	// Return empty JWT if configured
	if s.config.ReturnEmptyJWT {
		// Still record identity structure
		reqInfo.Identity = map[string]string{
			"provider":     string(identity.Provider),
			"identifier":   identity.Identifier,
			"accountID":    identity.AccountID,
			"region":       identity.Region,
			"resourceType": identity.ResourceType,
		}
		s.requestLog = append(s.requestLog, reqInfo)
		response := map[string]string{"jwt": ""}
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// Create JWT (also get claims used)
	tokenString, claims, err := s.createJWT(identity, jwtType)
	if err != nil {
		http.Error(w, fmt.Sprintf("error creating JWT: %v", err), http.StatusInternalServerError)
		return
	}

	// Attach structured identity and claims for test inspection
	reqInfo.Identity = map[string]string{
		"provider":     string(identity.Provider),
		"identifier":   identity.Identifier,
		"accountID":    identity.AccountID,
		"region":       identity.Region,
		"resourceType": identity.ResourceType,
	}
	// Copy claims map[string]interface{} to plain map (already map[string]interface{})
	reqInfo.Claims = make(map[string]interface{}, len(claims))
	for k, v := range claims {
		// Only include JSON-serializable simple values for clarity
		reqInfo.Claims[k] = v
	}

	s.requestLog = append(s.requestLog, reqInfo)

	response := map[string]string{"jwt": tokenString}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// createJWT generates a JWT for the given identity
func (s *Server) createJWT(identity *models.CloudIdentity, jwtType string) (string, jwt.MapClaims, error) {
	debugLog("===== GO TEST SERVER: Creating JWT with identity.Identifier: %s =====", identity.Identifier)
	debugLog("===== GO TEST SERVER: Creating JWT with identity.AccountID: %s =====", identity.AccountID)
	debugLog("===== GO TEST SERVER: Creating JWT with identity.Provider: %s =====", identity.Provider)
	debugLog("===== GO TEST SERVER: Setting JWT sub claim to: %s =====", identity.Identifier)

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":                 identity.Identifier,
		"provider":            identity.Provider,
		"accountID":           identity.AccountID,
		"region":              identity.Region,
		"resourceType":        identity.ResourceType,
		"jwtType":             jwtType,
		"createdByTestServer": true,
		"iat":                 now.Unix(),
		"exp":                 now.Add(s.config.TokenExpiry).Unix(),
	}

	// Add any additional properties, but never override above claims
	for key, value := range identity.AdditionalClaims {
		if _, ok := claims[key]; !ok {
			claims[key] = value
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(s.privateKey)
	return signed, claims, err
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
	_, _ = w.Write(pemData)
}

// handleRequestLog returns logged requests
func (s *Server) handleRequestLog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.requestLog)
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
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
