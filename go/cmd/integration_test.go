package main

import (
	"encoding/json"
	"errors"
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

const (
	serverInfoTimeoutSeconds = 10 // baseline timeout for local / fast environments
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
	infoFile := filepath.Join(t.TempDir(), "server-info.json")
	allArgs := append([]string{"--port", "0", "--info-file", infoFile}, args...)
	serverCmd := exec.Command(binary, allArgs...)
	serverCmd.Stderr = os.Stderr
	// Discard stdout entirely (we don't rely on it now)
	serverCmd.Stdout = nil
	if err := serverCmd.Start(); err != nil {
		return 0, nil, nil, fmt.Errorf("failed to start server: %w", err)
	}

	cleanup := func() {
		if runtime.GOOS == "windows" {
			_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprint(serverCmd.Process.Pid)).Run()
		} else {
			_ = serverCmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() { _ = serverCmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = serverCmd.Process.Kill()
			}
		}
	}

	deadline := time.Now().Add(time.Duration(serverInfoTimeoutSeconds) * time.Second)
	if os.Getenv("S2IAM_TEST_CLOUD_PROVIDER") != "" && serverInfoTimeoutSeconds < 30 {
		deadline = time.Now().Add(30 * time.Second)
	}

	var serverInfo ServerInfo
	for {
		data, err := os.ReadFile(infoFile)
		if err == nil {
			if jsonErr := json.Unmarshal(data, &serverInfo); jsonErr == nil && serverInfo.ServerInfo.Port > 0 {
				break
			}
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanup()
			return 0, nil, nil, fmt.Errorf("failed reading info file: %w", err)
		}
		if time.Now().After(deadline) {
			cleanup()
			return 0, nil, nil, fmt.Errorf("timed out waiting for info file")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if serverInfo.ServerInfo.Port <= 0 {
		cleanup()
		return 0, nil, nil, fmt.Errorf("invalid port in info file")
	}
	t.Logf("Server started on port %d (info file)", serverInfo.ServerInfo.Port)

	return serverInfo.ServerInfo.Port, serverInfo.ServerInfo.Endpoints, cleanup, nil
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
