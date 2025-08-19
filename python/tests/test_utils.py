"""
Test utilities and helpers for s2iam tests.
"""

import os
import sys
from pathlib import Path


def get_go_project_root() -> Path:
    """Get the Go project root directory."""
    current_dir = Path(__file__).parent
    go_dir = current_dir.parent.parent / "go"

    if not go_dir.exists():
        raise FileNotFoundError(f"Go project directory not found at {go_dir}")

    return go_dir


def is_cloud_environment() -> bool:
    """Check if we're running in a cloud environment."""
    # Check for common cloud environment indicators
    cloud_indicators = [
        # AWS
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_EXECUTION_ENV",
        # GCP
        "GCE_METADATA_HOST",
        "GOOGLE_CLOUD_PROJECT",
        # Azure
        "AZURE_CLIENT_ID",
        "MSI_ENDPOINT",
        "IDENTITY_ENDPOINT",
    ]

    return any(os.environ.get(indicator) for indicator in cloud_indicators)


def get_expected_provider() -> str:
    """Get the expected cloud provider based on environment."""
    if os.environ.get("AWS_REGION") or os.environ.get("AWS_EXECUTION_ENV"):
        return "aws"
    elif os.environ.get("GCE_METADATA_HOST") or os.environ.get("GOOGLE_CLOUD_PROJECT"):
        return "gcp"
    elif os.environ.get("AZURE_CLIENT_ID") or os.environ.get("MSI_ENDPOINT"):
        return "azure"
    else:
        return "unknown"


class SimpleTestLogger:
    """Simple test logger for debugging."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def log(self, message: str) -> None:
        """Log a message."""
        if self.verbose:
            print(f"[TEST] {message}", file=sys.stderr)


class TestUtilFunctions:
    """Test utility functions."""

    def test_expected_provider(self):
        """Test expected provider detection."""
        # This should return 'unknown' on regular GitHub runners
        provider = get_expected_provider()
        assert provider in ["aws", "gcp", "azure", "unknown"]

    def test_cloud_environment_detection(self):
        """Test cloud environment detection."""
        # This should return False on regular GitHub runners
        is_cloud = is_cloud_environment()
        assert isinstance(is_cloud, bool)

    def test_logger_creation(self):
        """Test logger creation."""
        logger = SimpleTestLogger(verbose=True)
        assert logger.verbose is True

        logger = SimpleTestLogger(verbose=False)
        assert logger.verbose is False
