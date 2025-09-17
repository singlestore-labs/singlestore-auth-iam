"""
Shared test utilities for managing the Go test server.
"""

import logging
import os
import subprocess
import json
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

        # Prepare info file path (atomic write by server)
        self.info_file = os.path.join(self.go_dir, "s2iam_test_server_info.json")

        # Prepare server command (request random port with 0 and info-file)
        server_cmd = [
            "./s2iam_test_server",
            "-port",
            str(self.port),
            "-timeout",
            f"{self.timeout_minutes}m",
            "-info-file",
            self.info_file,
            "-shutdown-on-stdin-close",
        ]
        logger.debug("Starting server with command: %s", " ".join(server_cmd))
        logger.debug("Server working directory: %s", self.go_dir)
        logger.debug(
            "Server environment variables: %s",
            {k: v for k, v in env.items() if k.startswith("S2IAM")},
        )

        # Start the server with timeout
        # We don't need stdout; server only writes JSON to file when info-file supplied
        self.process = subprocess.Popen(
            server_cmd,
            cwd=self.go_dir,
            env=env,
            stdin=subprocess.PIPE,  # so closing triggers shutdown if desired
            stdout=self._stderr_file,  # route to debug log; keep single sink
            stderr=self._stderr_file,
            text=True,
        )

        logger.debug("Server process started with PID: %s", self.process.pid)

        # Poll for info file instead of sleeping blindly
        logger.debug("Waiting for info file: %s", self.info_file)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.process.poll() is not None:
                # Process exited early
                with open(self.debug_log_file, "r", errors="ignore") as f:
                    debug_contents = f.read()
                raise Exception(
                    f"Test server exited early (code={self.process.returncode}); debug log:\n{debug_contents}"
                )
            try:
                with open(self.info_file, "r") as f:
                    info = json.load(f)
                port = info["server_info"]["port"]
                if port:
                    self.actual_port = port
                    break
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.debug("Info file read parse issue (continuing): %s", e)
            time.sleep(0.1)
        else:
            raise Exception("Timed out waiting for server info file")

        if not self.actual_port:
            raise Exception("Server did not provide a valid port in info file")

        # Update server_url with actual port
        self.server_url = f"http://localhost:{self.actual_port}"

        logger.debug("Test server started successfully on port %s", self.actual_port)

    # Removed _read_server_port; info-file polling replaces stdout parsing

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
