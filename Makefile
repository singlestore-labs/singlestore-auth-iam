# SingleStore Auth IAM Makefile
# Local development and cloud testing (when run on cloud VMs)

#------------------------------------------------------------------------------
# Directory scoping
#------------------------------------------------------------------------------
# We want a predictable, short-lived directory name for remote test runs.
# If the caller/exported environment provides a non-empty UNIQUE_DIR we use it.
# If it is unset OR set but empty, we generate a rotating default.

ifeq ($(strip $(UNIQUE_DIR)),)
UNIQUE_DIR := dev-$(shell echo $$(( ( $(shell date +%s) / 60 ) % 3 + 1 )))
endif
export UNIQUE_DIR

.PHONY: help test test-local test-go-local test-python-local on-remote-test on-remote-test-go on-remote-test-python check-cloud-env check-host clean \
 dev-setup-ubuntu dev-setup-macos \
 dev-setup-ubuntu-go dev-setup-ubuntu-python dev-setup-macos-go dev-setup-macos-python \
 dev-setup-common lint lint-go lint-python format format-go format-python ssh-copy-to-remote ssh-run-remote-tests ssh-download-coverage ssh-download-coverage-go ssh-download-coverage-python ssh-cleanup-remote

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
	@echo "  SSH Operations (for advanced usage):"
	@echo "    make ssh-copy-to-remote                 Copy code to remote HOST"
	@echo "    make ssh-run-remote-tests               Run TEST_TARGET on remote HOST"
	@echo "    make ssh-download-coverage              Download all coverage from remote HOST"
	@echo "    make ssh-download-coverage-go           Download Go coverage only"
	@echo "    make ssh-download-coverage-python       Download Python coverage only"
	@echo "    make ssh-cleanup-remote                 Clean up remote directory on HOST"
	@echo ""
	@echo "Development Setup:"
	@echo "  make dev-setup-ubuntu                     Full dev setup Ubuntu/Debian (Go + Python)"
	@echo "  make dev-setup-ubuntu-go                  Ubuntu/Debian Go toolchain + linters"
	@echo "  make dev-setup-ubuntu-python              Ubuntu/Debian Python tooling + deps"
	@echo "  make dev-setup-macos                      Full dev setup macOS (Go + Python)"
	@echo "  make dev-setup-macos-go                   macOS Go toolchain + linters"
	@echo "  make dev-setup-macos-python               macOS Python tooling + deps"
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
	! git grep -i 'jwt[ _]token'
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
	cd go && go test -v -failfast -covermode=atomic -coverprofile=coverage.out -coverpkg=github.com/singlestore-labs/singlestore-auth-iam/go/... ./...

on-remote-test-python: check-cloud-env
	@echo "=== Running Python cloud tests ==="
	@echo "Environment: S2IAM_TEST_CLOUD_PROVIDER=$${S2IAM_TEST_CLOUD_PROVIDER:-<unset>}"
	@echo "Environment: S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE=$${S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE:-<unset>}"
	@echo "Environment: S2IAM_TEST_ASSUME_ROLE=$${S2IAM_TEST_ASSUME_ROLE:-<unset>}"
	# Add src to PYTHONPATH so tests can import s2iam without installation
	cd python && PYTHONPATH=src python3 -m pytest tests/ -v --tb=short --cov=src/s2iam --cov-report=xml:coverage.xml --cov-report=html:htmlcov

dev-setup-ubuntu: dev-setup-ubuntu-go dev-setup-ubuntu-python
	@echo "✓ Full Ubuntu/Debian development environment ready"

dev-setup-macos: dev-setup-macos-go dev-setup-macos-python
	@echo "✓ Full macOS development environment ready"

dev-setup-common:
	sudo apt update
	sudo snap install go --classic || sudo apt install -y golang
	cd go && go mod download

dev-setup-ubuntu-go: dev-setup-common
	go install mvdan.cc/gofumpt@latest
	go install golang.org/x/tools/cmd/goimports@latest
	mkdir -p $$HOME/bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$HOME/bin v2.0.2
	@echo "✓ Ubuntu Go development environment ready"

dev-setup-macos-go:
	@if ! command -v brew >/dev/null 2>&1; then \
		echo "ERROR: Homebrew not found. Install from https://brew.sh first."; \
		exit 1; \
	fi
	brew install go golangci-lint
	cd go && go mod download
	go install mvdan.cc/gofumpt@latest
	go install golang.org/x/tools/cmd/goimports@latest
	@echo "✓ macOS Go development environment ready"

dev-setup-ubuntu-python: dev-setup-common
	sudo apt update
	sudo apt install -y python3 python3-pip python3-venv \
		python3-aiohttp python3-boto3 python3-google-auth python3-jwt python3-cryptography \
		python3-pytest python3-pytest-cov python3-pytest-asyncio python3-requests \
		python3-google-auth-oauthlib python3-flake8 black python3-mypy python3-isort
	@echo "Installing editable package with dev extras (pip) ..."
	cd python && pip install -e .[dev]
	@echo "✓ Ubuntu Python development environment ready (no virtualenv)"

dev-setup-macos-python:
	@if ! command -v brew >/dev/null 2>&1; then \
		echo "ERROR: Homebrew not found. Install from https://brew.sh first."; \
		exit 1; \
	fi
	brew install python3 pipx 
	python3 -m pip install --upgrade pip
	pipx ensurepath
	python3 -m pip install --upgrade \
		black isort flake8 mypy pytest pytest-cov pytest-asyncio aiohttp boto3 google-auth pyjwt cryptography requests google-auth-oauthlib
	cd python && pip3 install -e .[dev]
	@echo "✓ macOS Python development environment ready"

dev-setup-aws:
	sudo snap install aws-cli --classic

dev-setup-azure:
	@echo "Installing Azure CLI..."
	curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

dev-setup-gcp:
	@echo "GCP dependencies installed via python3-google-auth and python3-google-auth-oauthlib"

lint: lint-go lint-python

lint-go:
	@echo "Running Go linters..."
	cd go && go vet ./...
	cd go && golangci-lint run
	# Fail if gofumpt would reformat any files
	cd go && FMPT_OUT=$$(gofumpt -l .); if [ -n "$$FMPT_OUT" ]; then \
		echo "ERROR: gofumpt formatting needed in these files:"; \
		echo "$$FMPT_OUT"; \
		echo "Run 'make format-go' to fix."; \
		exit 1; \
	fi
	# Fail if goimports would modify any files
	cd go && GIMP_OUT=$$(goimports -l .); if [ -n "$$GIMP_OUT" ]; then \
		echo "ERROR: goimports formatting needed in these files:"; \
		echo "$$GIMP_OUT"; \
		echo "Run 'make format-go' to fix."; \
		exit 1; \
	fi

lint-python:
	@echo "Running Python linters..."
	cd python && python3 -m mypy src
	cd python && python3 -m flake8 --max-line-length=120 --extend-ignore=E203,W503,F841,F541 src/ tests/
	cd python && python3 -m black --check src/ tests/
	cd python && python3 -m isort --check-only src tests

format: format-go format-python

format-go:
	@echo "Formatting Go code..."
	cd go && gofumpt -w .
	cd go && goimports -w .

format-python:
	@echo "Formatting Python code..."
	cd python && python3 -m black src/ tests/
	cd python && python3 -m isort src tests

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
REMOTE_BASE_DIR ?= tests
SSH_OPTS ?= -o StrictHostKeyChecking=no -o ConnectTimeout=10

# SSH operations (low-level operations for copying code and running tests)
# CI target - copy code to remote host
ssh-copy-to-remote: check-host
	@echo "Copying tracked files to $(HOST) in directory $(REMOTE_BASE_DIR)/$(UNIQUE_DIR)..."
	git ls-files -z | tar -czf - --null -T - | \
		ssh $(SSH_OPTS) $(HOST) \
		"mkdir -p $(REMOTE_BASE_DIR)/$(UNIQUE_DIR) && cd $(REMOTE_BASE_DIR)/$(UNIQUE_DIR) && tar xzf -"

# CI target - run tests on remote host
ssh-run-remote-tests: check-host
	@echo "Running tests on $(HOST) with environment: $(ENV_VARS)"
	ssh $(SSH_OPTS) $(HOST) \
		"cd $(REMOTE_BASE_DIR)/$(UNIQUE_DIR) && env $(ENV_VARS) make $(TEST_TARGET) on-remote-completed" \
		2>&1 | tee $(HOST)-log
	@if grep -q "✓ All tests completed successfully" $(HOST)-log; then \
		echo "✓ Remote tests passed on $(HOST)"; \
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
	TIMESTAMP=$$(date +%Y%m%d-%H%M%S); \
	scp $(SSH_OPTS) $(HOST):$(REMOTE_BASE_DIR)/$(UNIQUE_DIR)/go/coverage.out ./go-coverage-$$TIMESTAMP.out; \
	if [ ! -s ./go-coverage-$$TIMESTAMP.out ]; then echo "Go coverage file empty or missing"; exit 1; fi; \
	cp ./go-coverage-$$TIMESTAMP.out go-coverage.out

# CI target - download Python coverage from remote host
ssh-download-coverage-python: check-host
	@echo "Downloading Python coverage from $(HOST)..."
	TIMESTAMP=$$(date +%Y%m%d-%H%M%S); \
	scp $(SSH_OPTS) $(HOST):$(REMOTE_BASE_DIR)/$(UNIQUE_DIR)/python/coverage.xml ./python-coverage-$$TIMESTAMP.xml; \
	if [ ! -s ./python-coverage-$$TIMESTAMP.xml ]; then echo "Python coverage file empty or missing"; exit 1; fi; \
	cp ./python-coverage-$$TIMESTAMP.xml python-coverage.xml

# Generic function to cleanup remote directory
# CI target - cleanup remote directory
ssh-cleanup-remote: check-host
	@echo "Cleaning up remote directory on $(HOST)..."
	ssh $(SSH_OPTS) $(HOST) "rm -rf $(REMOTE_BASE_DIR)/$(UNIQUE_DIR)"


