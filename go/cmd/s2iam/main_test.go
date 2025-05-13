package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
		validate    func(t *testing.T, config Config)
	}{
		{
			name: "database jwt with workspace",
			args: []string{"cmd", "--workspace-group-id", "test-workspace"},
			validate: func(t *testing.T, config Config) {
				assert.Equal(t, "database", config.JWTType)
				assert.Equal(t, "test-workspace", config.WorkspaceGroupID)
			},
		},
		{
			name: "api jwt",
			args: []string{"cmd", "--jwt-type", "api"},
			validate: func(t *testing.T, config Config) {
				assert.Equal(t, "api", config.JWTType)
			},
		},
		{
			name: "with provider and role",
			args: []string{"cmd", "--provider", "aws", "--assume-role", "test-role", "--workspace-group-id", "test-workspace"},
			validate: func(t *testing.T, config Config) {
				assert.Equal(t, "aws", config.Provider)
				assert.Equal(t, "test-role", config.AssumeRole)
			},
		},
		{
			name: "environment output",
			args: []string{"cmd", "--env-name", "TOKEN", "--env-status", "STATUS", "--workspace-group-id", "test-workspace"},
			validate: func(t *testing.T, config Config) {
				assert.Equal(t, "TOKEN", config.EnvName)
				assert.Equal(t, "STATUS", config.EnvStatus)
			},
		},
		{
			name: "verbose mode",
			args: []string{"cmd", "--verbose", "--workspace-group-id", "test-workspace"},
			validate: func(t *testing.T, config Config) {
				assert.True(t, config.Verbose)
			},
		},
		{
			name:        "missing workspace group id",
			args:        []string{"cmd", "--jwt-type", "database"},
			expectError: true,
			errorMsg:    "--workspace-group-id is required",
		},
		{
			name:        "invalid jwt type",
			args:        []string{"cmd", "--jwt-type", "invalid"},
			expectError: true,
			errorMsg:    "invalid JWT type",
		},
		{
			name:        "invalid provider",
			args:        []string{"cmd", "--provider", "invalid", "--workspace-group-id", "test-workspace"},
			expectError: true,
			errorMsg:    "invalid provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flagSet := flag.NewFlagSet(tt.args[0], flag.ContinueOnError)
			// Capture stderr to prevent output during tests
			flagSet.SetOutput(&bytes.Buffer{})

			config, err := parseFlags(flagSet, tt.args)

			if tt.expectError {
				assert.Error(t, err, "Expected an error for test case: %s", tt.name)
				if tt.errorMsg != "" {
					assert.True(t, strings.Contains(err.Error(), tt.errorMsg),
						"Expected error message to contain '%s', but got: '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			assert.NoError(t, err, "Unexpected error for test case: %s: %v", tt.name, err)
			if tt.validate != nil {
				tt.validate(t, config)
			}
		})
	}
}

func TestRun_Success(t *testing.T) {
	// Check if we're on a cloud provider
	ctx := context.Background()
	_, err := s2iam.DetectProvider(ctx, s2iam.WithTimeout(2*time.Second))
	onCloudProvider := err == nil

	// Create a test server that returns a JWT
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple mock that returns a JWT
		response := map[string]string{"jwt": "test-jwt-token"}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := Config{
		JWTType:          "database",
		WorkspaceGroupID: "test-workspace",
		ServerURL:        server.URL + "/auth/iam/:jwtType",
		Timeout:          time.Second,
	}

	// If we're on a cloud provider, use the actual provider
	// Otherwise, use the mock server which will work without real credentials
	if onCloudProvider {
		config.Provider = "" // Auto-detect
	} else {
		// Skip this test if not on cloud provider and no mock available
		t.Skip("test requires cloud provider or mock credentials")
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = run(config)

	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	require.NoError(t, err)
	assert.Contains(t, output, "test-jwt-token")
}

// TestRun_EnvironmentOutput tests the environment variable output functionality
func TestRun_EnvironmentOutput(t *testing.T) {
	// Check if we're on a cloud provider
	ctx := context.Background()
	_, err := s2iam.DetectProvider(ctx, s2iam.WithTimeout(2*time.Second))
	if err != nil {
		t.Skip("Skipping TestRun_EnvironmentOutput - not on cloud provider")
	}

	// Create a test server that returns a JWT
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{"jwt": "test-jwt-token"}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := Config{
		JWTType:          "database",
		WorkspaceGroupID: "test-workspace",
		ServerURL:        server.URL + "/auth/iam/:jwtType",
		EnvName:          "TOKEN",
		EnvStatus:        "STATUS",
		Timeout:          time.Second,
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = run(config)

	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	require.NoError(t, err)
	assert.Contains(t, output, "STATUS=0")
	assert.Contains(t, output, "TOKEN=test-jwt-token")
}

// TestRun_Error tests the error handling in the run function
func TestRun_Error(t *testing.T) {
	// Check if we're on a cloud provider
	ctx := context.Background()
	_, err := s2iam.DetectProvider(ctx, s2iam.WithTimeout(2*time.Second))
	if err != nil {
		t.Skip("Skipping TestRun_Error - not on cloud provider")
	}

	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
	}))
	defer server.Close()

	config := Config{
		JWTType:          "database",
		WorkspaceGroupID: "test-workspace",
		ServerURL:        server.URL + "/auth/iam/:jwtType",
		Timeout:          time.Second,
	}

	err = run(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication")
}

func TestGetLogger(t *testing.T) {
	// Test with verbose disabled
	logger := getLogger(Config{Verbose: false})
	assert.Nil(t, logger)

	// Test with verbose enabled
	logger = getLogger(Config{Verbose: true})
	assert.NotNil(t, logger)
}

// TestRealMain tests the realMain function
func TestRealMain(t *testing.T) {
	// We'll split the tests into cloud-dependent and non-cloud-dependent tests
	cloudTests := []struct {
		name     string
		args     []string
		exitCode int
		wantErr  bool
		wantOut  string
		errMsg   string
	}{
		{
			name: "valid database jwt",
			args: []string{
				"cmd",
				"--workspace-group-id", "test-workspace",
				"--server-url", "http://mock-server/auth/iam/:jwtType", // Will be replaced if test runs
			},
			exitCode: 0,
			wantErr:  false,
			wantOut:  "test-jwt-token",
		},
	}

	validationTests := []struct {
		name     string
		args     []string
		exitCode int
		wantErr  bool
		wantOut  string
		errMsg   string
	}{
		{
			name: "invalid jwt type",
			args: []string{
				"cmd",
				"--jwt-type", "invalid",
			},
			exitCode: 1,
			wantErr:  true,
			errMsg:   "invalid JWT type",
		},
		{
			name: "missing workspace id",
			args: []string{
				"cmd",
				"--jwt-type", "database",
			},
			exitCode: 1,
			wantErr:  true,
			errMsg:   "--workspace-group-id is required",
		},
	}

	// Check if we're on a cloud provider
	ctx := context.Background()
	_, err := s2iam.DetectProvider(ctx, s2iam.WithTimeout(2*time.Second))
	onCloudProvider := err == nil

	// Run cloud-independent validation tests
	for _, tt := range validationTests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout and stderr
			oldStdout := os.Stdout
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stdout = w
			os.Stderr = w

			// Mock exit function
			mockExit := func(code int) {
			}

			err := realMain(tt.args, mockExit)

			w.Close()
			os.Stdout = oldStdout
			os.Stderr = oldStderr

			// Read captured output
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r)

			assert.Error(t, err, "Expected an error for test case: %s", tt.name)
			if tt.errMsg != "" {
				assert.True(t, strings.Contains(err.Error(), tt.errMsg),
					"Expected error message to contain '%s', but got: '%s'", tt.errMsg, err.Error())
			}
		})
	}

	// Only run cloud-dependent tests if we're on a cloud provider
	if !onCloudProvider {
		t.Logf("Skipping cloud-dependent tests - not on cloud provider")
		return
	}

	// Create a test server that returns a JWT
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{"jwt": "test-jwt-token"}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Update server URL in cloud tests
	for i := range cloudTests {
		cloudTests[i].args[len(cloudTests[i].args)-1] = server.URL + "/auth/iam/:jwtType"
	}

	// Run cloud-dependent tests
	for _, tt := range cloudTests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout and stderr
			oldStdout := os.Stdout
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stdout = w
			os.Stderr = w

			// Mock exit function
			exitCalled := false
			exitCode := 0
			mockExit := func(code int) {
				exitCalled = true
				exitCode = code
			}

			err := realMain(tt.args, mockExit)

			w.Close()
			os.Stdout = oldStdout
			os.Stderr = oldStderr

			// Read captured output
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r)
			output := buf.String()

			assert.NoError(t, err, "Unexpected error for test case: %s: %v", tt.name, err)
			assert.Contains(t, output, tt.wantOut)

			// Only verify exitCode if the exit function was actually called
			if exitCalled {
				assert.Equal(t, tt.exitCode, exitCode)
			}
		})
	}
}

func TestMain_Help(t *testing.T) {
	// Capture stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w

	// Run with help flag
	args := []string{"cmd", "-h"}
	flagSet := flag.NewFlagSet(args[0], flag.ContinueOnError)
	// Setting output to avoid actual printing during tests
	flagSet.SetOutput(w)

	_, err := parseFlags(flagSet, args)
	assert.Error(t, err, "Help flag should trigger an error")
	assert.Equal(t, flag.ErrHelp, err, "Expected flag.ErrHelp")

	// Restore stdout and stderr
	w.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	// Read captured output
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Help output should contain usage information
	assert.Contains(t, output, "Usage:")
	assert.Contains(t, output, "Options:")
}
