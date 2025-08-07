"""
Shared test utilities for managing the Go test server.
"""

import os
import subprocess
import time
from typing import Optional


class GoTestServerManager:
    """Manages the Go test server for integration and validation tests."""

    def __init__(self, port: int = 8080, go_dir: Optional[str] = None):
        self.port = port
        self.process: Optional[subprocess.Popen] = None
        self.server_url = f"http://localhost:{port}"
        self.go_dir = self._get_go_directory(go_dir)

    def _get_go_directory(self, go_dir: Optional[str]) -> str:
        """Get the Go directory location for the two known test scenarios."""
        if go_dir:
            if not os.path.exists(os.path.join(go_dir, "go.mod")):
                raise Exception(f"Specified Go directory does not contain go.mod: {go_dir}")
            return os.path.abspath(go_dir)
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Both CI and remote testing have the same relative structure:
        # CI: /repo/python/tests/ -> /repo/go/ 
        # Remote: /tests/test-retest-N/python/tests/ -> /tests/test-retest-N/go/
        go_dir = os.path.join(current_dir, "../../go")
        
        if not os.path.exists(os.path.join(go_dir, "go.mod")):
            raise Exception(f"Go directory with go.mod not found at: {go_dir}")
        
        return os.path.abspath(go_dir)

    def start(self) -> None:
        """Start the Go test server."""
        if self.process and self.process.poll() is None:
            print(f"DEBUG: Test server already running on port {self.port}")
            return  # Already running

        print(f"DEBUG: Starting Go test server on port {self.port}")
        print(f"DEBUG: Using Go directory: {self.go_dir}")

        # Build the test server
        print("DEBUG: Building test server...")
        build_result = subprocess.run(
            ["go", "build", "-o", "s2iam_test_server", "./cmd/s2iam_test_server"],
            cwd=self.go_dir,
            capture_output=True,
            text=True,
        )

        if build_result.returncode != 0:
            print(f"DEBUG: Build failed with stderr: {build_result.stderr}")
            print(f"DEBUG: Build failed with stdout: {build_result.stdout}")
            raise Exception(f"Failed to build test server: {build_result.stderr}")
        
        print("DEBUG: Build successful, starting server...")

        # Set debug log file for Go server
        debug_log_file = os.path.join(self.go_dir, "test_server_debug.log")
        self.debug_log_file = debug_log_file  # Store for later access
        env = os.environ.copy()
        env["S2IAM_TEST_SERVER_DEBUG_LOG"] = debug_log_file
        
        print(f"DEBUG: Go server debug log will be written to: {debug_log_file}")

        # Start the server
        self.process = subprocess.Popen(
            ["./s2iam_test_server", "-port", str(self.port)],
            cwd=self.go_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        print(f"DEBUG: Server process started with PID: {self.process.pid}")

        # Wait for server to start
        time.sleep(2)

        if self.process.poll() is not None:
            stdout, stderr = self.process.communicate()
            print(f"DEBUG: Server failed to start - stdout: {stdout}")
            print(f"DEBUG: Server failed to start - stderr: {stderr}")
            raise Exception(f"Test server failed to start: {stderr}")
        
        print("DEBUG: Test server started successfully")

    def stop(self) -> None:
        """Stop the Go test server."""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None

        # Show debug log contents if available
        self.show_debug_log()

    def show_debug_log(self) -> None:
        """Display the contents of the Go server debug log."""
        if hasattr(self, 'debug_log_file') and os.path.exists(self.debug_log_file):
            print(f"\n===== GO SERVER DEBUG LOG CONTENTS =====")
            try:
                with open(self.debug_log_file, 'r') as f:
                    contents = f.read().strip()
                    if contents:
                        print(contents)
                    else:
                        print("(Debug log file is empty)")
            except Exception as e:
                print(f"Error reading debug log: {e}")
            print("===== END GO SERVER DEBUG LOG =====\n")
        else:
            print("DEBUG: No Go server debug log file found")

    def is_running(self) -> bool:
        """Check if the test server is running."""
        return self.process is not None and self.process.poll() is None

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
