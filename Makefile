
.PHONY: help test test-local test-go-local test-python-local on-remote-test on-remote-test-go on-remote-test-python check-cloud-env check-host clean install install-go install-python lint lint-go lint-python format format-go format-python ssh-copy-to-remote ssh-run-remote-tests ssh-download-coverage ssh-download-coverage-go ssh-download-coverage-python ssh-cleanup-remote launch-remote launch-remote-go launch-remote-python launch-remote-go-only launch-remote-python-only launch-all-go launch-all-python

# Default target
help:
	@echo "SingleStore Auth IAM Build System"
	@echo ""
	@echo "Local Testing:"
	@echo "  make test                                 Run all local tests (Go + Python)"
	@echo "  make test-go-local                        Run Go local tests"
	@echo "  make test-python-local                    Run Python local tests"
	@echo ""
	@echo "Cloud Testing (run ON cloud VMs - these targets work when you're ON the cloud host):"
	@echo "  make on-remote-test                       Run cloud tests (Go + Python)"
	@echo "  make on-remote-test-go                    Run Go cloud tests only"
	@echo "  make on-remote-test-python                Run Python cloud tests only"
	@echo ""
	@echo "Remote Testing (launch FROM local machine TO cloud VMs via SSH):"
	@echo "  Local Development Patterns:"
	@echo "    1. Single language + single host:"
	@echo "      make launch-remote-go                 Complete Go workflow (copy/test/download/cleanup)"
	@echo "      make launch-remote-python             Complete Python workflow (copy/test/download/cleanup)"
	@echo "    2. Single language + all hosts:"
	@echo "      make launch-all-go                    Test Go across all cloud providers"
	@echo "      make launch-all-python                Test Python across all cloud providers"
	@echo "    3. Specific cloud provider testing (requires external env setup):"
	@echo "      make launch-aws-positive              Test both languages on AWS positive"
	@echo "      make launch-aws-negative              Test both languages on AWS negative"
	@echo "      make launch-gcp-positive              Test both languages on GCP positive"
	@echo "      make launch-gcp-negative              Test both languages on GCP negative"
	@echo "      make launch-azure-positive            Test both languages on Azure positive"
	@echo "      make launch-azure-negative            Test both languages on Azure negative"
	@echo "    4. Language-specific cloud testing (requires external env setup):"
	@echo "      make launch-aws-positive-go           Test Go only on AWS positive"
	@echo "      make launch-gcp-negative-python       Test Python only on GCP negative"
	@echo "      (All combinations: {aws|gcp|azure}-{positive|negative}-{go|python})"
	@echo "    5. Generic remote testing:"
	@echo "      make launch-remote                    Run tests on specified HOST with ENV_VARS"
	@echo ""
	@echo "  SSH Operations (for advanced usage):"
	@echo "    make ssh-copy-to-remote                 Copy code to remote HOST"
	@echo "    make ssh-run-remote-tests               Run TEST_TARGET on remote HOST"
	@echo "    make ssh-download-coverage              Download all coverage from remote HOST"
	@echo "    make ssh-download-coverage-go           Download Go coverage only"
	@echo "    make ssh-download-coverage-python       Download Python coverage only"
	@echo "    make ssh-cleanup-remote                 Clean up remote directory on HOST"
	@echo ""
	@echo "Installation:"
	@echo "  make install                              Install all dependencies"
	@echo "  make install-go                           Install Go dependencies"
	@echo "  make install-python                       Install Python dependencies"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint                                 Run all linters"
	@echo "  make format                               Format all code"
	@echo "  make clean                                Clean build artifacts"
	@echo ""
	@echo "Environment Variables for Cloud Testing:"
	@echo "  S2IAM_TEST_CLOUD_PROVIDER=gcp|azure|aws  Enable positive cloud tests"
	@echo "  S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE=gcp|azure|aws  Enable negative cloud tests"
	@echo "  S2IAM_TEST_ASSUME_ROLE=arn:...            Enable AWS role assumption tests"
	@echo "  S2IAM_DEBUGGING=true                      Enable verbose test output"
	@echo ""
	@echo "Required for Remote Testing:"
	@echo "  HOST=user@hostname                        Target host for remote testing"
	@echo "  ENV_VARS=\"VAR1=val1 VAR2=val2\"           Environment variables for remote tests"
	@echo ""
	@echo "For Cloud Provider Specific Targets (set externally):"
	@echo "  AWS_POSITIVE_HOST=user@hostname           AWS positive test host"
	@echo "  AWS_POSITIVE_ENV_VARS=\"S2IAM_TEST_...\"    AWS positive environment variables"
	@echo "  (Similar pattern for AWS_NEGATIVE_*, GCP_POSITIVE_*, GCP_NEGATIVE_*,"
	@echo "   AZURE_POSITIVE_*, AZURE_NEGATIVE_*)"
	@echo ""
	@echo "Coverage files are automatically timestamped (e.g., go-coverage-20250807-143022.out)"

# Test targets
test: test-local
	@echo "✓ All local tests completed"

test-local: test-go-local test-python-local
	@echo "✓ All local tests passed"

test-go-local:
	@echo "Running Go local tests..."
	cd go && go test -v ./...

test-python-local:
	@echo "Running Python local tests..."
	cd python && python3 -m pytest tests/ -v

check-cloud-env:
	@if [ -z "$$S2IAM_TEST_CLOUD_PROVIDER" ] && [ -z "$$S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE" ] && [ -z "$$S2IAM_TEST_ASSUME_ROLE" ]; then \
		echo "ERROR: No S2IAM_TEST_* environment variable set. Cloud tests require one of:"; \
		echo "  S2IAM_TEST_CLOUD_PROVIDER=aws|gcp|azure"; \
		echo "  S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE=aws|gcp|azure"; \
		echo "  S2IAM_TEST_ASSUME_ROLE=arn:..."; \
		exit 1; \
	fi

check-host:
ifndef HOST
	$(error HOST environment variable must be set (e.g., user@hostname))
endif

on-remote-completed: 
	@echo "✓ All tests completed successfully"

# Cloud test targets (designed to run ON cloud VMs)
on-remote-test: check-cloud-env on-remote-test-go on-remote-test-python

on-remote-test-go: check-cloud-env
	@echo "=== Running Go cloud tests ==="
	@echo "Environment: S2IAM_TEST_CLOUD_PROVIDER=$${S2IAM_TEST_CLOUD_PROVIDER:-<unset>}"
	@echo "Environment: S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE=$${S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE:-<unset>}"
	@echo "Environment: S2IAM_TEST_ASSUME_ROLE=$${S2IAM_TEST_ASSUME_ROLE:-<unset>}"
	cd go && go test -v --failfast ./...
	cd go && go test -covermode=atomic -coverprofile=coverage.out -coverpkg=github.com/singlestore-labs/singlestore-auth-iam/... ./...

on-remote-test-python: check-cloud-env
	cd python && PYTHONPATH=src python3 -m pytest tests/ -v --tb=short
	cd python && PYTHONPATH=src python3 -m pytest tests/ --cov=src/s2iam --cov-report=xml:coverage.xml --cov-report=html:htmlcov

install: install-go install-python
	@echo "✓ All dependencies installed"

install-common:
	sudo apt update
	sudo snap install go --classic

install-go:
	@echo "Installing Go dependencies..."
	cd go && go mod download
	cd go && go mod tidy
	go install mvdan.cc/gofumpt@latest
	go install golang.org/x/tools/cmd/goimports@latest
	mkdir -p $$HOME/bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$HOME/bin v2.0.2

install-python: install-go
	@echo "Installing Python dependencies..."
	sudo apt install -y python3 python3-pip python3-venv \
		python3-aiohttp python3-boto3 python3-google-auth python3-jwt python3-cryptography \
		python3-pytest python3-pytest-cov python3-pytest-asyncio python3-requests \
		python3-google-auth-oauthlib python3-flake8 black python3-mypy python3-isort
	cd python && pip install -e .

# Cloud provider specific installations
install-aws:
	@echo "Installing AWS CLI..."
	sudo snap install aws-cli --classic

install-azure:
	@echo "Installing Azure CLI..."
	curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

install-gcp:
	@echo "GCP dependencies installed via python3-google-auth and python3-google-auth-oauthlib"

lint: lint-go lint-python

lint-go:
	@echo "Running Go linters..."
	cd go && go vet ./...
	cd go && golangci-lint run

lint-python:
	@echo "Running Python linters..."
	cd python && python3 -m flake8 --max-line-length=120 src tests 
	cd python && python3 -m black --check src tests
	cd python && isort --check-only src tests
	cd python && mypy src

format: format-go format-python

format-go:
	@echo "Formatting Go code..."
	cd go && gofumpt -w .
	cd go && goimports -w .

format-python:
	@echo "Formatting Python code..."
	cd python && python3 -m black src/ tests/ || echo "black not available, skipping"

# Clean targets
clean:
	@echo "Cleaning build artifacts..."
	cd go && go clean -testcache
	cd python && rm -rf build/ dist/ *.egg-info/ .pytest_cache/ htmlcov/ coverage.xml
	@echo "✓ Build artifacts cleaned"

#==============================================================================
# Remote Cloud Testing Infrastructure
#==============================================================================

# Variables for remote testing (can be overridden by environment or GitHub Actions)
# Use := to evaluate once at parse time rather than each time it's used
UNIQUE_DIR ?= dev-$(shell echo $$(( ( $(shell date +%s) / 60 ) % 3 + 1 )))
REMOTE_BASE_DIR ?= tests
SSH_OPTS ?= -o StrictHostKeyChecking=no -o ConnectTimeout=10

# SSH operations (low-level operations for copying code and running tests)
# CI target - copy code to remote host
# Copy only tracked files to avoid sending local artifacts (venv, caches, logs)
ssh-copy-to-remote: check-host
	@echo "Copying code to $(HOST) in directory $(REMOTE_BASE_DIR)/$(UNIQUE_DIR)..."
	git ls-files -z | tar -czf - --null -T - | \
		ssh $(SSH_OPTS) $(HOST) \
		"mkdir -p $(REMOTE_BASE_DIR)/$(UNIQUE_DIR) && cd $(REMOTE_BASE_DIR)/$(UNIQUE_DIR) && tar xzf -";

# CI target - run tests on remote host
ssh-run-remote-tests: check-host
	@echo "Running tests on $(HOST) with environment: $(ENV_VARS)"
	@ssh $(SSH_OPTS) $(HOST) \
		"cd $(REMOTE_BASE_DIR)/$(UNIQUE_DIR) && env $(ENV_VARS) make $(TEST_TARGET) on-remote-completed" \
		2>&1 | tee $(HOST)-log
	@if grep -q "✓ All tests completed successfully" $(HOST)-log; then \
		echo "✓ Remote tests passed on $(HOST)"; \
		$(MAKE) ssh-download-coverage; \
	else \
		echo "✗ Remote tests failed on $(HOST) - check $(HOST)-log"; \
		exit 1; \
	fi

# Generic function to download coverage files
# CI target - download coverage files from remote host
ssh-download-coverage: ssh-download-coverage-go ssh-download-coverage-python
	@echo "✓ All coverage files downloaded"

# CI target - download Go coverage from remote host
ssh-download-coverage-go: check-host
	@echo "Downloading Go coverage from $(HOST)..."
	@TIMESTAMP=$$(date +%Y%m%d-%H%M%S); \
	scp $(SSH_OPTS) $(HOST):$(REMOTE_BASE_DIR)/$(UNIQUE_DIR)/go/coverage.out ./go-coverage-$$TIMESTAMP.out 2>/dev/null || echo "No Go coverage file found"

# CI target - download Python coverage from remote host
ssh-download-coverage-python: check-host
	@echo "Downloading Python coverage from $(HOST)..."
	@TIMESTAMP=$$(date +%Y%m%d-%H%M%S); \
	scp $(SSH_OPTS) $(HOST):$(REMOTE_BASE_DIR)/$(UNIQUE_DIR)/python/coverage.xml ./python-coverage-$$TIMESTAMP.xml 2>/dev/null || echo "No Python coverage file found"

# Generic function to cleanup remote directory
# CI target - cleanup remote directory
ssh-cleanup-remote: check-host
	@echo "Cleaning up remote directory on $(HOST)..."
	@ssh $(SSH_OPTS) $(HOST) "rm -rf $(REMOTE_BASE_DIR)/$(UNIQUE_DIR)" || true

# Complete remote test cycle - copy, test, download, cleanup (LAUNCHED FROM local machine)
# CI target - used by GitHub Actions cloud_provider_makefile.yml
launch-remote: check-host ssh-copy-to-remote ssh-run-remote-tests ssh-cleanup-remote
	@echo "✓ Remote testing completed (success)"

# Convenience targets for individual components
launch-remote-go-only:
	@$(MAKE) ssh-run-remote-tests TEST_TARGET="on-remote-test-go"

launch-remote-python-only:
	@$(MAKE) ssh-run-remote-tests TEST_TARGET="on-remote-test-python"

# Complete test workflows for individual languages (LAUNCHED FROM local machine)
launch-remote-go: check-host ssh-copy-to-remote launch-remote-go-only ssh-cleanup-remote
	@echo "✓ Remote Go testing completed (success)"

launch-remote-python: check-host ssh-copy-to-remote launch-remote-python-only ssh-cleanup-remote
	@echo "✓ Remote Python testing completed (success)"

# Test single language across all hosts (LAUNCHED FROM local machine)
# Note: Requires environment variables to be set for each cloud provider
launch-all-go: launch-aws-positive-go launch-gcp-positive-go launch-azure-positive-go launch-aws-negative-go launch-gcp-negative-go launch-azure-negative-go

launch-all-python: launch-aws-positive-python launch-gcp-positive-python launch-azure-positive-python launch-aws-negative-python launch-gcp-negative-python launch-azure-negative-python

# Specific cloud provider targets (LAUNCHED FROM local machine)
# Note: These require environment variables to be set externally

# Pattern rule for cloud provider testing (handles all combinations)
# Examples: launch-aws-positive, launch-gcp-negative-go, launch-azure-positive-python
launch-%: 
	@$(eval PARTS := $(subst -, ,$*))
	@$(eval PROVIDER := $(word 1,$(PARTS)))
	@$(eval TYPE := $(word 2,$(PARTS)))
	@$(eval LANG := $(word 3,$(PARTS)))
	@$(eval PROVIDER_UPPER := $(shell echo $(PROVIDER) | tr a-z A-Z))
	@$(eval TYPE_UPPER := $(shell echo $(TYPE) | tr a-z A-Z))
	@$(eval HOST_VAR := $(PROVIDER_UPPER)_$(TYPE_UPPER)_HOST)
	@$(eval ENV_VAR := $(PROVIDER_UPPER)_$(TYPE_UPPER)_ENV_VARS)
	@$(eval HOST_VALUE := $($(HOST_VAR)))
	@$(eval ENV_VALUE := $($(ENV_VAR)))
	@$(eval LAUNCH_UNIQUE_DIR := dev-$(shell echo $$(( ( $(shell date +%s) / 60 ) % 3 + 1 ))))
	@echo "=== $(PROVIDER_UPPER) $(TYPE_UPPER) $(if $(LANG),$(shell echo $(LANG) | tr a-z A-Z) ,)Testing ==="
	@if [ -z "$(HOST_VALUE)" ]; then echo "ERROR: $(HOST_VAR) not set"; exit 1; fi
	@if [ -z "$(ENV_VALUE)" ]; then echo "ERROR: $(ENV_VAR) not set"; exit 1; fi
	@$(MAKE) $(if $(LANG),launch-remote-$(LANG),launch-remote) HOST="$(HOST_VALUE)" ENV_VARS="$(ENV_VALUE)" UNIQUE_DIR="$(LAUNCH_UNIQUE_DIR)"


