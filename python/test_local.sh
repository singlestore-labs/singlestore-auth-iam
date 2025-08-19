#!/bin/bash -e

# Quick test script for Python s2iam library
# Run this locally to test the library before pushing to cloud environments

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_DIR="$SCRIPT_DIR"

echo "Testing Python s2iam library locally..."

cd "$PYTHON_DIR"

# Check if we have Python 3
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Check if we're in a cloud environment
CLOUD_ENV=""
if [ -n "${AWS_REGION:-}" ] || [ -n "${AWS_EXECUTION_ENV:-}" ]; then
    CLOUD_ENV="aws"
elif [ -n "${GCE_METADATA_HOST:-}" ] || [ -n "${GOOGLE_CLOUD_PROJECT:-}" ]; then
    CLOUD_ENV="gcp"
elif [ -n "${AZURE_CLIENT_ID:-}" ] || [ -n "${MSI_ENDPOINT:-}" ]; then
    CLOUD_ENV="azure"
fi

if [ -n "$CLOUD_ENV" ]; then
    echo "✓ Detected cloud environment: $CLOUD_ENV"
    echo "Running full integration tests..."
    export S2IAM_DEBUGGING=true
    ./test_integration.sh
else
    echo "⚠ No cloud environment detected"
    echo "Running unit tests only..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d ".venv" ]; then
        echo "Creating Python virtual environment..."
        python3 -m venv .venv
    fi
    
    # Activate virtual environment
    source .venv/bin/activate
    
    # Install dependencies
    echo "Installing dependencies..."
    pip install --upgrade pip
    pip install -e ".[dev]"
    pip install aiohttp
    
    # Run unit tests only
    echo "Running unit tests..."
    python -m pytest tests/test_models.py -v
    
    echo "✓ Unit tests completed successfully!"
    echo "Note: Integration tests require running in a cloud environment"
fi

echo "Local testing completed!"
