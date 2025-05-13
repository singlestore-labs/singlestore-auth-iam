package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_ServerAndClient tests the test server and client working together
func TestIntegration_ServerAndClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// First, check if we're on a cloud provider
	ctx := context.Background()
	_, err := s2iam.DetectProvider(ctx, s2iam.WithTimeout(2*time.Second))
	if err != nil {
		t.Skip("test requires a cloud provider")
	}

	// Build both commands
	testServerBinary := t.TempDir() + "/test_server"
	clientBinary := t.TempDir() + "/client"

	// Build test server
	cmd := exec.Command("go", "build", "-o", testServerBinary, "./cmd/s2iam_test_server")
	err = cmd.Run()
	require.NoError(t, err, "failed to build test server")

	// Build client
	cmd = exec.Command("go", "build", "-o", clientBinary, "./cmd/s2iam")
	err = cmd.Run()
	require.NoError(t, err, "failed to build client")

	// Start test server
	serverCmd := exec.Command(testServerBinary, "--port", "8888")
	err = serverCmd.Start()
	require.NoError(t, err, "failed to start test server")
	defer serverCmd.Process.Kill()

	// Wait for server to start
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for {
		resp, err := http.Get("http://localhost:8888/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("server failed to start")
		case <-time.After(100 * time.Millisecond):
			continue
		}
	}

	// Run client against test server - should succeed with real cloud provider
	clientCmd := exec.Command(clientBinary,
		"--server-url", "http://localhost:8888/auth/iam/:jwtType",
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
	resp, err := http.Get("http://localhost:8888/info/requests")
	require.NoError(t, err)

	var requests []interface{}
	err = json.NewDecoder(resp.Body).Decode(&requests)
	require.NoError(t, err)

	// Should have at least one request from the client
	assert.GreaterOrEqual(t, len(requests), 1)
}

// TestIntegration_ServerOnly tests just the server functionality
func TestIntegration_ServerOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Build test server
	testServerBinary := t.TempDir() + "/test_server"
	cmd := exec.Command("go", "build", "-o", testServerBinary, "./cmd/s2iam_test_server")
	err := cmd.Run()
	require.NoError(t, err, "failed to build test server")

	// Start test server with various configurations
	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T)
	}{
		{
			name: "basic server",
			args: []string{"--port", "8889"},
			check: func(t *testing.T) {
				resp, err := http.Get("http://localhost:8889/health")
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		{
			name: "server with error response",
			args: []string{"--port", "8890", "--return-error", "--error-code", "503"},
			check: func(t *testing.T) {
				resp, err := http.Post("http://localhost:8890/auth/iam/database", "", nil)
				require.NoError(t, err)
				assert.Equal(t, 503, resp.StatusCode)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverCmd := exec.Command(testServerBinary, tt.args...)
			err := serverCmd.Start()
			require.NoError(t, err, "failed to start test server")
			defer serverCmd.Process.Kill()

			// Wait for server to start
			time.Sleep(500 * time.Millisecond)

			tt.check(t)
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
