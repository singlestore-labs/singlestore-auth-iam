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
        build_result = subprocess.run(
            ["go", "build", "-o", "s2iam_test_server", "./cmd/s2iam_test_server"],
            cwd=self.go_dir,
            capture_output=True,
            text=True,
        )

        if build_result.returncode != 0:
            logger.debug("Build failed with stderr: %s", build_result.stderr)
            logger.debug("Build failed with stdout: %s", build_result.stdout)
            raise Exception(f"Failed to build test server: {build_result.stderr}")

        logger.debug("Build successful, starting server...")

        # Set debug log file for Go server
        debug_log_file = os.path.join(self.go_dir, "test_server_debug.log")
        self.debug_log_file = debug_log_file  # Store for later access
        env = os.environ.copy()
        env["S2IAM_TEST_SERVER_DEBUG_LOG"] = debug_log_file

        logger.debug("Go server debug log will be written to: %s", debug_log_file)

        # Start the server with timeout
        self.process = subprocess.Popen(
            [
                "./s2iam_test_server",
                "-port",
                str(self.port),
                "-timeout",
                f"{self.timeout_minutes}m",
            ],
            cwd=self.go_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        logger.debug("Server process started with PID: %s", self.process.pid)

        # Wait for server to start
        time.sleep(2)

        if self.process.poll() is not None:
            stdout, stderr = self.process.communicate()
            logger.debug("Server failed to start - stdout: %s", stdout)
            logger.debug("Server failed to start - stderr: %s", stderr)
            raise Exception(f"Test server failed to start: {stderr}")

        # If we used port 0, read the actual port from server output
        if self.port == 0:
            self.actual_port = self._read_server_port()
        else:
            self.actual_port = self.port

        # Update server_url with actual port
        self.server_url = f"http://localhost:{self.actual_port}"

        logger.debug("Test server started successfully on port %s", self.actual_port)

    def _read_server_port(self) -> int:
        """Read the server port from JSON output."""
        import json

        # The Go server prints JSON with server_info containing the port
        # Read stdout until we find the JSON object
        start_time = time.time()
        timeout = 10  # 10 second timeout
        buffer = ""

        while time.time() - start_time < timeout:
            if self.process.stdout:
                try:
                    line = self.process.stdout.readline()
                    if line:
                        buffer += line
                        # Try to parse JSON when we have a complete object
                        if buffer.strip().startswith("{") and buffer.strip().endswith("}"):
                            try:
                                server_info = json.loads(buffer.strip())
                                port = server_info["server_info"]["port"]
                                logger.debug("Got server port %s from JSON", port)
                                return port
                            except (json.JSONDecodeError, KeyError):
                                # Not valid JSON or missing port, keep reading
                                pass
                except Exception as e:
                    logger.debug("Error reading stdout: %s", e)
                    break
            time.sleep(0.1)

        raise Exception("Could not read server port from JSON output")

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
        if hasattr(self, "debug_log_file") and os.path.exists(self.debug_log_file):
            print(f"\n===== GO SERVER DEBUG LOG CONTENTS =====")
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
