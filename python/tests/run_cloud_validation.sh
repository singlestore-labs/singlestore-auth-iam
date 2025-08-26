#!/bin/bash
set -e

# Cloud validation test runner for s2iam Python library
# This script can run locally and in CI/CD environments

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}


print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if cloud tests should run
should_run_cloud_tests() {
    # Cloud tests should run if test environment variables are set
    if [ -n "${S2IAM_TEST_CLOUD_PROVIDER:-}" ] || [ -n "${S2IAM_TEST_ASSUME_ROLE:-}" ]; then
        return 0  # true - run cloud tests
    else
        return 1  # false - skip cloud tests
    fi
}

# Function to install dependencies if needed
setup_environment() {
    print_status "Setting up test environment..."
    
    cd "$PYTHON_DIR"
    
    # Ensure Go is available in this SSH session too (CI may start a fresh session per step)
    # Common install paths: snap (/snap/bin) and tarball (/usr/local/go/bin)
    export PATH="/usr/local/go/bin:/snap/bin:$PATH"
    if command -v go >/dev/null 2>&1; then
        print_status "go found: $(go version)"
    else
        print_error "go not found on PATH (required for building test server)"; exit 1
    fi
    
    # Check if we should use system packages (when USE_SYSTEM_PACKAGES=1)
    if [ "${USE_SYSTEM_PACKAGES:-0}" = "1" ]; then
        print_status "Using system packages (skipping virtual environment creation)"
        
        # Check if required system packages are available
        if python3 -c "import aiohttp, pytest" 2>/dev/null; then
            print_success "System packages available - using system Python environment"
            python3 -m pip install -e . --user --break-system-packages
            print_success "Environment setup complete (using system packages)"
            return 0
        else
            print_error "Required system packages not available (aiohttp, pytest). Aborting."
            exit 1
        fi
    fi
    
    # Create virtual environment if it doesn't exist
    if [ ! -d ".venv" ]; then
        print_status "Creating virtual environment..."
        python3 -m venv .venv
    fi
    
    # Activate virtual environment
    source .venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install package in development mode
    print_status "Installing s2iam package and dependencies..."
    pip install -e '.[dev]'
    
    print_success "Environment setup complete"
}

# Function to run tests
run_tests() {
    local test_mode="$1"
    
    cd "$PYTHON_DIR"
    
    # Only activate virtual environment if we're not using system packages
    if [ "${USE_SYSTEM_PACKAGES:-0}" != "1" ]; then
        source .venv/bin/activate
    fi
    
    # Base pytest command with fail-fast option
    local pytest_cmd="pytest -v --maxfail=1"
    
    # Add coverage if requested
    if [[ "$test_mode" == "coverage" ]]; then
        print_status "Adding coverage reporting..."
        pytest_cmd="$pytest_cmd --cov=src/s2iam --cov-report=term-missing --cov-report=html --cov-report=xml"
    fi
    
    # Run all tests - the tests themselves will skip appropriately based on environment variables
    pytest_cmd="$pytest_cmd tests/"
    
    print_status "Running: $pytest_cmd"
    
    if should_run_cloud_tests; then
        print_status "Environment variables indicate cloud tests should run"
    else
        print_status "No cloud test environment variables set - cloud tests will be skipped"
    fi
    
    if eval "$pytest_cmd"; then
        print_success "All tests passed!"
        return 0
    else
        print_error "Some tests failed!"
        return 1
    fi
}

# Function to run quick validation
run_quick_validation() {
    cd "$PYTHON_DIR"
    
    # Only activate virtual environment if not using system packages
    if [ "${USE_SYSTEM_PACKAGES:-0}" != "1" ]; then
        source .venv/bin/activate
    fi
    
    print_status "Running quick validation tests..."
    
    if should_run_cloud_tests; then
        print_status "Environment variables indicate cloud tests should run"
    else
        print_status "No cloud test environment variables set - tests will skip appropriately"
    fi
    
    # Run only the core validation tests
    if pytest -v -x tests/test_cloud_validation.py::TestCloudProviderValidation::test_provider_detection_and_identity; then
        print_success "Quick validation passed!"
        return 0
    else
        print_error "Quick validation failed!"
        return 1
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --setup           Setup test environment only"
    echo "  --quick           Run quick validation tests only"
    echo "  --coverage        Run tests with coverage reporting"
    echo "  --help            Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  S2IAM_TEST_CLOUD_PROVIDER    Set to 'aws', 'gcp', or 'azure' to run cloud tests"
    echo "  S2IAM_TEST_ASSUME_ROLE       Set to role ARN/ID to test role assumption"
    echo "  S2IAM_DEBUGGING              Set to 'true' for verbose test output"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run tests (cloud tests skip if no env vars)"
    echo "  $0 --quick                           # Run quick validation only"
    echo "  $0 --coverage                        # Run with coverage reporting"
    echo "  S2IAM_TEST_CLOUD_PROVIDER=aws $0     # Run tests expecting AWS to work"
}

# Main execution
main() {
    local setup_only=false
    local quick_only=false
    local coverage_mode=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --setup)
                setup_only=true
                shift
                ;;
            --quick)
                quick_only=true
                shift
                ;;
            --coverage)
                coverage_mode="coverage"
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Setup environment
    setup_environment
    
    if [ "$setup_only" = true ]; then
        print_success "Setup complete!"
        exit 0
    fi
    
    # Run tests
    if [ "$quick_only" = true ]; then
        run_quick_validation
    else
        run_tests "$coverage_mode"
    fi
    
    exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        print_success "Test run completed successfully!"
    else
        print_error "Test run failed!"
    fi
    
    exit $exit_code
}

# Run main function with all arguments
main "$@"
