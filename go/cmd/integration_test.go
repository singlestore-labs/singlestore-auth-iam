package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/singlestore-labs/singlestore-auth-iam/go/internal/testhelp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// toString safely converts interface{} to string for comparison purposes.
func toString(val interface{}) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

// Define a struct for parsing the server info JSON
type ServerInfo struct {
	ServerInfo struct {
		Port      int                    `json:"port"`
		Endpoints map[string]string      `json:"endpoints"`
		Config    map[string]interface{} `json:"config"`
	} `json:"server_info"`
}

// startServerWithRandomPort starts a server with a random port and returns the port and endpoints
func startServerWithRandomPort(t *testing.T, binary string, args []string) (int, map[string]string, func(), error) {
	// Start test server with port 0 to use a random port
	allArgs := append([]string{"--port", "0"}, args...)
	serverCmd := exec.Command(binary, allArgs...)

	// Set up proper pipes for Windows compatibility
	serverCmd.Stderr = os.Stderr // Send errors to test output

	// Capture server output to get the JSON info
	serverOutput, err := serverCmd.StdoutPipe()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to get server stdout: %w", err)
	}

	// Start the process
	if err := serverCmd.Start(); err != nil {
		return 0, nil, nil, fmt.Errorf("failed to start server: %w", err)
	}

	// Prepare a robust cleanup function
	cleanup := func() {
		// First try graceful termination
		if runtime.GOOS == "windows" {
			// Windows-specific process termination using taskkill
			// This is more reliable than Process.Kill() on Windows
			_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprint(serverCmd.Process.Pid)).Run()
		} else {
			// On Unix systems, send SIGTERM first for graceful shutdown
			_ = serverCmd.Process.Signal(syscall.SIGTERM)

			// Give it a moment to terminate gracefully
			done := make(chan struct{})
			go func() {
				_ = serverCmd.Wait()
				close(done)
			}()

			// If it doesn't exit gracefully within a timeout, force kill it
			select {
			case <-done:
				// Process exited cleanly
			case <-time.After(2 * time.Second):
				// Force kill if it doesn't exit
				_ = serverCmd.Process.Kill()
			}
		}
	}

	// Read server output to find the JSON info
	scanner := bufio.NewScanner(serverOutput)
	var serverInfo ServerInfo
	infoFound := make(chan bool, 1)

	go func() {
		var jsonData strings.Builder
		var jsonStarted bool

		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("Server: %s", line)

			// Look for the start of the JSON data
			if !jsonStarted && strings.Contains(line, "{") {
				jsonStarted = true
				jsonData.WriteString(line)
			} else if jsonStarted {
				jsonData.WriteString(line)

				// Check if this could be the end of the JSON
				if strings.Contains(line, "}") {
					// Try to parse what we have, being more lenient with JSON structure
					jsonStr := jsonData.String()
					jsonStr = strings.Join(strings.Fields(jsonStr), "")

					// Try to find valid JSON even if there's other text in the output
					startIdx := strings.Index(jsonStr, "{")
					endIdx := strings.LastIndex(jsonStr, "}")
					if startIdx >= 0 && endIdx > startIdx {
						validJson := jsonStr[startIdx : endIdx+1]
						if err := json.Unmarshal([]byte(validJson), &serverInfo); err == nil {
							if serverInfo.ServerInfo.Port > 0 {
								infoFound <- true
								break
							}
						}
					}
				}
			}
		}
	}()

	// Wait for the server info to be found or timeout
	select {
	case <-infoFound:
		t.Logf("Server started on port %d", serverInfo.ServerInfo.Port)
	case <-time.After(10 * time.Second):
		cleanup()
		return 0, nil, nil, fmt.Errorf("timed out waiting for server info")
	}

	// Wait for server to respond to health checks with a timeout
	healthURL := serverInfo.ServerInfo.Endpoints["health"]
	healthCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use a client with timeout for health checks
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Retry loop with backoff for health checks
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		resp, err := httpClient.Get(healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			return serverInfo.ServerInfo.Port, serverInfo.ServerInfo.Endpoints, cleanup, nil
		}
		if err != nil {
			t.Logf("Health check failed: %v (retry %d/%d)", err, i+1, maxRetries)
		}

		// Check if context has been canceled
		select {
		case <-healthCtx.Done():
			cleanup()
			return 0, nil, nil, fmt.Errorf("server failed to respond to health checks: %v", healthCtx.Err())
		case <-time.After(500 * time.Millisecond * time.Duration(i+1)): // Increasing backoff
			continue
		}
	}

	cleanup()
	return 0, nil, nil, fmt.Errorf("server failed to respond to health checks after %d attempts", maxRetries)
}

// TestIntegration_ServerAndClient tests the test server and client working together
func TestIntegration_ServerAndClient(t *testing.T) {
	_ = testhelp.RequireCloudRole(t)

	// Build both commands with platform-specific binary names
	binaryExt := ""
	if runtime.GOOS == "windows" {
		binaryExt = ".exe"
	}

	testServerBinary := filepath.Join(t.TempDir(), "test_server"+binaryExt)
	clientBinary := filepath.Join(t.TempDir(), "client"+binaryExt)

	// Get the absolute path to the project's Go module
	moduleRoot, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	require.NoError(t, err, "failed to determine module root")
	moduleRootStr := strings.TrimSpace(string(moduleRoot))

	// Build test server using absolute paths
	testServerPath := filepath.Join(moduleRootStr, "cmd", "s2iam_test_server")
	cmd := exec.Command("go", "build", "-o", testServerBinary, testServerPath)
	err = cmd.Run()
	require.NoError(t, err, "failed to build test server")

	// Build client using absolute paths
	clientPath := filepath.Join(moduleRootStr, "cmd", "s2iam")
	cmd = exec.Command("go", "build", "-o", clientBinary, clientPath)
	err = cmd.Run()
	require.NoError(t, err, "failed to build client")

	// Start the server with random port and get endpoints
	_, endpoints, cleanup, err := startServerWithRandomPort(t, testServerBinary, nil)
	require.NoError(t, err, "failed to start server")
	defer cleanup()

	// Run client against test server - should succeed with real cloud provider
	clientCmd := exec.Command(clientBinary,
		"--server-url", endpoints["auth"],
		"--jwt-type", "api",
		"--env-name", "TOKEN",
		"--env-status", "STATUS")

	output, err := clientCmd.CombinedOutput()
	require.NoError(t, err, "client failed: %s", string(output))

	// Should have successful output
	outputStr := string(output)
	assert.Contains(t, outputStr, "STATUS=0")
	assert.Contains(t, outputStr, "TOKEN=")
	assert.NotContains(t, outputStr, "TOKEN=\n") // Should have actual token

	// Check server's request log
	resp, err := http.Get(endpoints["requests"])
	require.NoError(t, err)

	var requests []map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&requests)
	require.NoError(t, err)

	// Should have at least one request from the client
	assert.GreaterOrEqual(t, len(requests), 1)

	// Strict identity vs claim comparison: create CloudIdentity from claims and compare whole struct
	for _, req := range requests {
		claims, ok := req["claims"].(map[string]interface{})
		identityMap, ok2 := req["identity"].(map[string]interface{})
		if !ok || !ok2 {
			t.Fatalf("Request missing claims or identity: %+v", req)
		}

		// Build CloudIdentity from claims
		claimIdentity := struct {
			Provider     string
			Identifier   string
			AccountID    string
			Region       string
			ResourceType string
		}{
			Provider:     toString(claims["provider"]),
			Identifier:   toString(claims["sub"]),
			AccountID:    toString(claims["accountID"]),
			Region:       toString(claims["region"]),
			ResourceType: toString(claims["resourceType"]),
		}

		// Build CloudIdentity from identity map
		actualIdentity := struct {
			Provider     string
			Identifier   string
			AccountID    string
			Region       string
			ResourceType string
		}{
			Provider:     toString(identityMap["provider"]),
			Identifier:   toString(identityMap["identifier"]),
			AccountID:    toString(identityMap["accountID"]),
			Region:       toString(identityMap["region"]),
			ResourceType: toString(identityMap["resourceType"]),
		}

		assert.Equal(t, actualIdentity, claimIdentity, "CloudIdentity mismatch: claim=%+v identity=%+v", claimIdentity, actualIdentity)
	}
}

// TestIntegration_ServerOnly tests just the server functionality
func TestIntegration_ServerOnly(t *testing.T) {
	// Build test server with platform-specific binary extension
	binaryExt := ""
	if runtime.GOOS == "windows" {
		binaryExt = ".exe"
	}

	testServerBinary := filepath.Join(t.TempDir(), "test_server"+binaryExt)

	moduleRoot, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	require.NoError(t, err, "failed to determine module root")
	moduleRootStr := strings.TrimSpace(string(moduleRoot))

	testServerPath := filepath.Join(moduleRootStr, "cmd", "s2iam_test_server")
	cmd := exec.Command("go", "build", "-o", testServerBinary, testServerPath)
	err = cmd.Run()
	require.NoError(t, err, "failed to build test server")

	// Start test server with various configurations
	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, port int, endpoints map[string]string)
	}{
		{
			name: "basic server",
			args: []string{},
			check: func(t *testing.T, port int, endpoints map[string]string) {
				resp, err := http.Get(endpoints["health"])
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		{
			name: "server with error response",
			args: []string{"--return-error", "--error-code", "503"},
			check: func(t *testing.T, port int, endpoints map[string]string) {
				// Extract the base URL without the :jwtType parameter
				authURL := strings.Replace(endpoints["auth"], ":jwtType", "database", 1)
				resp, err := http.Post(authURL, "", nil)
				require.NoError(t, err)
				assert.Equal(t, 503, resp.StatusCode)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start server with the specified arguments and get endpoints
			serverPort, endpoints, cleanup, err := startServerWithRandomPort(t, testServerBinary, tt.args)
			require.NoError(t, err, "failed to start server")
			defer cleanup()

			// Run the test check with the port and endpoints
			tt.check(t, serverPort, endpoints)
		})
	}
}

// TestUsage_Examples provides example usage that can be referenced
func TestUsage_Examples(t *testing.T) {
	examples := []struct {
		name        string
		description string
		command     string
	}{
		{
			name:        "basic database jwt",
			description: "Get a database JWT for a workspace",
			command:     "s2iam --workspace-group-id=my-workspace",
		},
		{
			name:        "api jwt",
			description: "Get an API JWT",
			command:     "s2iam --jwt-type=api",
		},
		{
			name:        "environment variables",
			description: "Output for shell evaluation",
			command:     "eval $(s2iam --env-status=STATUS --env-name=TOKEN --workspace-group-id=my-workspace)",
		},
		{
			name:        "test server basic",
			description: "Start test server on default port",
			command:     "s2iam_test_server",
		},
		{
			name:        "test server with errors",
			description: "Test server that fails verification",
			command:     "s2iam_test_server --fail-verification",
		},
	}

	// This test just documents examples
	for _, ex := range examples {
		t.Run(ex.name, func(t *testing.T) {
			t.Logf("Example: %s\nCommand: %s", ex.description, ex.command)
		})
	}
}
