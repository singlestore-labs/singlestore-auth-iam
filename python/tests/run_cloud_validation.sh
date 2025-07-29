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

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect current environment
detect_environment() {
    print_status "Detecting cloud environment..."
    
    if curl -s --max-time 2 -H "Metadata-Flavor: Google" \
       "http://metadata.google.internal/computeMetadata/v1/" > /dev/null 2>&1; then
        echo "gcp"
    elif curl -s --max-time 2 \
       "http://169.254.169.254/latest/meta-data/" > /dev/null 2>&1; then
        echo "aws"
    elif curl -s --max-time 2 -H "Metadata: true" \
       "http://169.254.169.254/metadata/instance" > /dev/null 2>&1; then
        echo "azure"
    else
        echo "local"
    fi
}

# Function to install dependencies if needed
setup_environment() {
    print_status "Setting up test environment..."
    
    cd "$PYTHON_DIR"
    
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

# Function to run tests with appropriate markers
run_tests() {
    local environment="$1"
    local test_mode="$2"
    
    cd "$PYTHON_DIR"
    source .venv/bin/activate
    
    print_status "Running tests for environment: $environment"
    
    # Base pytest command
    local pytest_cmd="pytest -v"
    
    # Add coverage if requested
    if [[ "$coverage_mode" == "coverage" ]]; then
        print_status "Adding coverage reporting..."
        pytest_cmd="$pytest_cmd --cov=src/s2iam --cov-report=term-missing --cov-report=html --cov-report=xml"
    fi
    
    # Add specific test markers based on environment
    case "$environment" in
        "gcp")
            pytest_cmd="$pytest_cmd -m 'integration and (not aws and not azure)'"
            ;;
        "aws")
            pytest_cmd="$pytest_cmd -m 'integration and (not gcp and not azure)'"
            ;;
        "azure")
            pytest_cmd="$pytest_cmd -m 'integration and (not gcp and not aws)'"
            ;;
        "local")
            pytest_cmd="$pytest_cmd -m 'not integration'"
            print_warning "Running in local environment - skipping cloud integration tests"
            ;;
        "all")
            pytest_cmd="$pytest_cmd"
            ;;
    esac
    
    # Add cloud validation tests
    pytest_cmd="$pytest_cmd tests/test_cloud_validation.py tests/test_models.py"
    
    print_status "Running: $pytest_cmd"
    
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
    local environment="$1"
    
    cd "$PYTHON_DIR"
    source .venv/bin/activate
    
    print_status "Running quick validation tests..."
    
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
    echo "  --environment ENV Specify environment (gcp, aws, azure, local, all)"
    echo "  --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Auto-detect environment and run appropriate tests"
    echo "  $0 --quick           # Run quick validation only"
    echo "  $0 --coverage        # Run with coverage reporting"
    echo "  $0 --environment gcp # Force GCP environment tests"
}

# Main execution
main() {
    local setup_only=false
    local quick_only=false
    local coverage_mode=""
    local forced_environment=""
    
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
            --environment)
                forced_environment="$2"
                shift 2
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
    
    # Detect or use forced environment
    if [ -n "$forced_environment" ]; then
        environment="$forced_environment"
        print_status "Using forced environment: $environment"
    else
        environment=$(detect_environment)
        print_status "Detected environment: $environment"
    fi
    
    # Run tests
    if [ "$quick_only" = true ]; then
        run_quick_validation "$environment"
    else
        run_tests "$environment" "$coverage_mode"
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
