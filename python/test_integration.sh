#!/bin/bash

# Script to run Python integration tests
# This script is designed to be run in a cloud environment as part of CI/CD

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_DIR="$SCRIPT_DIR"
GO_DIR="$SCRIPT_DIR/../go"

echo "Setting up Python environment for s2iam tests..."

# Create virtual environment if it doesn't exist
if [ ! -d "$PYTHON_DIR/.venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "$PYTHON_DIR/.venv"
fi

# Activate virtual environment
source "$PYTHON_DIR/.venv/bin/activate"

# Upgrade pip and install package in development mode
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -e ".[dev]"

# Install aiohttp which is needed for async HTTP requests
pip install aiohttp

echo "Running Python tests..."

# Set environment variable for debugging if requested
if [ "${S2IAM_DEBUGGING:-}" = "true" ]; then
    export S2IAM_DEBUGGING=true
    echo "Debug logging enabled"
fi

# Run unit tests first (these don't require cloud environment)
echo "Running unit tests..."
python -m pytest tests/test_models.py -v

# Run integration tests (cloud provider expectations enforced by test code skips/fails)
echo "Running full integration test suite..."
python -m pytest tests/test_integration.py -v

echo "Python tests completed successfully."
