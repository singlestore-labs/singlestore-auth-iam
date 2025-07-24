"""
Shared test utilities for managing the Go test server.
"""

import os
import subprocess
import time
from typing import Optional


class GoTestServerManager:
    """Manages the Go test server for integration and validation tests."""
    
    def __init__(self, port: int = 8080):
        self.port = port
        self.process: Optional[subprocess.Popen] = None
        self.server_url = f"http://localhost:{port}"
        self.go_dir = None
        self._find_go_directory()
    
    def _find_go_directory(self):
        """Find the Go directory relative to the test file."""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Try different relative paths to find go.mod
        possible_paths = [
            os.path.join(current_dir, "../../go"),
            os.path.join(current_dir, "../../../go"),
            os.path.join(current_dir, "../../../../go"),
        ]
        
        for path in possible_paths:
            if os.path.exists(os.path.join(path, "go.mod")):
                self.go_dir = os.path.abspath(path)
                break
        
        if not self.go_dir:
            raise Exception("Could not find Go directory with go.mod")
    
    def start(self) -> None:
        """Start the Go test server."""
        if self.process and self.process.poll() is None:
            return  # Already running
        
        # Build the test server
        build_result = subprocess.run(
            ["go", "build", "-o", "s2iam_test_server", "./cmd/s2iam_test_server"],
            cwd=self.go_dir,
            capture_output=True,
            text=True
        )
        
        if build_result.returncode != 0:
            raise Exception(f"Failed to build test server: {build_result.stderr}")
        
        # Start the server
        self.process = subprocess.Popen(
            ["./s2iam_test_server", "-port", str(self.port)],
            cwd=self.go_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for server to start
        time.sleep(2)
        
        if self.process.poll() is not None:
            stdout, stderr = self.process.communicate()
            raise Exception(f"Test server failed to start: {stderr}")
    
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
