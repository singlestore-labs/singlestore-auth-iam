"""
Shared test utilities for managing the Go test server.
"""

import logging
import os
import subprocess
import time
from typing import Optional

logger = logging.getLogger(__name__)


class GoTestServerManager:
    """Manages the Go test server for integration and validation tests."""

    def __init__(
        self,
        port: Optional[int] = None,
        go_dir: Optional[str] = None,
        timeout_minutes: int = 5,
    ):
        # Use port 0 to let the Go server pick a random port
        # This is more reliable than trying to find a free port ourselves
        self.port = port if port is not None else 0
        self.timeout_minutes = timeout_minutes
        self.process: Optional[subprocess.Popen] = None
        self.server_url = f"http://localhost:{self.port}"  # Will be updated after server starts
        self.go_dir = self._get_go_directory(go_dir)
        self.actual_port: Optional[int] = None

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
            logger.debug("Test server already running on port %s", self.port)
            return  # Already running

        logger.debug("Starting Go test server on port %s", self.port)
        logger.debug("Using Go directory: %s", self.go_dir)

        # Build the test server
        logger.debug("Building test server...")
        logger.debug("Build command: go build -o s2iam_test_server ./cmd/s2iam_test_server")
        logger.debug("Build working directory: %s", self.go_dir)

        build_result = subprocess.run(
            ["go", "build", "-o", "s2iam_test_server", "./cmd/s2iam_test_server"],
            cwd=self.go_dir,
            capture_output=True,
            text=True,
        )

        if build_result.returncode != 0:
            logger.error("Build failed with return code: %s", build_result.returncode)
            logger.error("Build failed with stderr: %s", build_result.stderr)
            logger.error("Build failed with stdout: %s", build_result.stdout)
            raise Exception(f"Failed to build test server: {build_result.stderr}")

        logger.debug("Build successful, starting server...")

        # Verify binary was created and is executable
        binary_path = os.path.join(self.go_dir, "s2iam_test_server")
        if not os.path.exists(binary_path):
            logger.error("Binary not found after build: %s", binary_path)
            raise Exception(f"Test server binary not found after build: {binary_path}")

        if not os.access(binary_path, os.X_OK):
            logger.error("Binary not executable: %s", binary_path)
            raise Exception(f"Test server binary not executable: {binary_path}")

        logger.debug("Binary verified: %s (size: %d bytes)", binary_path, os.path.getsize(binary_path))

        # Set debug log file for Go server
        debug_log_file = os.path.join(self.go_dir, "test_server_debug.log")
        self.debug_log_file = debug_log_file  # Store for later access
        env = os.environ.copy()
        env["S2IAM_TEST_SERVER_DEBUG_LOG"] = debug_log_file
        # Also route process stderr to this file to keep stdout clean for JSON
        self._stderr_file = open(debug_log_file, "w")

        logger.debug("Go server debug log will be written to: %s", debug_log_file)

        # Prepare server command
        server_cmd = [
            "./s2iam_test_server",
            "-port",
            str(self.port),
            "-timeout",
            f"{self.timeout_minutes}m",
        ]
        logger.debug("Starting server with command: %s", ' '.join(server_cmd))
        logger.debug("Server working directory: %s", self.go_dir)
        logger.debug(
            "Server environment variables: %s",
            {k: v for k, v in env.items() if k.startswith("S2IAM")},
        )

        # Start the server with timeout
        self.process = subprocess.Popen(
            server_cmd,
            cwd=self.go_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file,
            text=True,
            bufsize=1,  # line-buffered for text mode
        )

        logger.debug("Server process started with PID: %s", self.process.pid)

        # Wait for server to start - increased wait time for CI
        logger.debug("Waiting for server to initialize...")
        time.sleep(3)  # Increased from 2 to 3 seconds

        # Check if process is still running
        poll_result = self.process.poll()
        if poll_result is not None:
            stdout, stderr = self.process.communicate()
            logger.error(
                "Server failed to start - process exited with code: %s", poll_result
            )
            logger.error("Server failed to start - stdout: %s", stdout)
            logger.error("Server failed to start - stderr: %s", stderr)
            raise Exception(
                f"Test server failed to start (exit code: {poll_result}): {stderr}"
            )

        logger.debug("Server process still running, attempting to read port...")

        # If we used port 0, read the actual port from server output
        if self.port == 0:
            self.actual_port = self._read_server_port()
        else:
            self.actual_port = self.port

        # Update server_url with actual port
        self.server_url = f"http://localhost:{self.actual_port}"

        logger.debug("Test server started successfully on port %s", self.actual_port)

    def _read_server_port(self) -> int:
        """Read the server port from JSON written to stdout (synchronous, simple)."""
        import json

        start_time = time.time()
        timeout = 30  # seconds
        buffer = ""
        all_stdout: list[str] = []
        brace_count = 0
        in_json = False

        logger.debug("Reading server port from JSON output (timeout=%ds)...", timeout)

        while time.time() - start_time < timeout:
            if not self.process or self.process.poll() is not None:
                logger.error("Server process ended while reading port")
                break

            # Blocking read of one line; server prints pretty JSON with newlines
            line = self.process.stdout.readline() if self.process and self.process.stdout else ""
            if not line:
                time.sleep(0.05)
                continue

            all_stdout.append(line)
            buffer += line
            logger.debug("STDOUT: %s", line.rstrip())

            for ch in line:
                if ch == '{':
                    brace_count += 1
                    in_json = True
                elif ch == '}':
                    brace_count -= 1

            if in_json and brace_count == 0:
                js_start = buffer.find('{')
                js_end = buffer.rfind('}') + 1
                if js_start >= 0 and js_end > js_start:
                    js = buffer[js_start:js_end]
                    try:
                        obj = json.loads(js)
                        port = obj["server_info"]["port"]
                        logger.debug("Parsed port from JSON: %s", port)
                        return port
                    except Exception as e:
                        logger.debug("JSON parse failed (continuing): %s", e)
                        buffer = ""
                        brace_count = 0
                        in_json = False

        logger.error("Failed to read server port within %ds", timeout)
        logger.error("All stdout received:\n%s", ''.join(all_stdout))
        if self.process:
            logger.error("Server process exit code: %s", self.process.poll())
        raise Exception(f"Could not read server port from JSON output after {timeout}s timeout")

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

        # Ensure stderr file is closed
        if hasattr(self, "_stderr_file") and self._stderr_file and not self._stderr_file.closed:
            try:
                self._stderr_file.flush()
            except Exception:
                pass
            try:
                self._stderr_file.close()
            except Exception:
                pass

        # Show debug log contents if available
        self.show_debug_log()

    def show_debug_log(self) -> None:
        """Display the contents of the Go server debug log."""
        if hasattr(self, "debug_log_file") and os.path.exists(self.debug_log_file):
            print("\n===== GO SERVER DEBUG LOG CONTENTS =====")
            try:
                with open(self.debug_log_file, "r") as f:
                    contents = f.read().strip()
                    if contents:
                        print(contents)
                    else:
                        print("(Debug log file is empty)")
            except Exception as e:
                print(f"Error reading debug log: {e}")
            print("===== END GO SERVER DEBUG LOG =====\n")
        else:
            logger.debug("No Go server debug log file found")

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
