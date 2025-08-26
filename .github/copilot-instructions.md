# Copilot Instructions for SingleStore Auth IAM

## Project Overview

This is a **cloud provider authentication library** that only really works when running on actual cloud service providers (AWS, GCP, Azure). The library detects the current cloud environment and provides JWT tokens for database and API access using cloud provider identities.

**Key Point:** This is not a typical library that can be fully tested locally - it requires real cloud metadata services to function properly.

## Language Implementation Status

- **Go**: ✅ First and primary implementation. Passes all tests on real CSPs. Tests run in seconds.
- **Python**: 🔄 Secondary implementation. **Goal: Achieve Go equivalency.**
- **Other languages**: Future implementations must also achieve Go equivalency.

## Architecture

**What Users Actually Use:** The simple convenience API is what matters most:
```python
# This is what real users care about
jwt = await s2iam.get_jwt_database(workspace_group_id="my-workspace")
jwt = await s2iam.get_jwt_api()
```

## Testing Philosophy

### Fail-fast rule

- Do not mask, swallow, or downgrade any failure
- Remove all uses of || true, conditional fallbacks, and warning-only branches.
- Treat coverage download, cleanup, and verification steps as mandatory; any failure exits non‑zero immediately.
- Do not aggregate errors; stop at first failing command.
- Preserve and surface the original failing command’s output (no quiet suppression).
- No “warn” or “optional” wording—only success or hard failure.

### Performance Requirements
- **Tests should fail CSP detection quickly** so tests run fast in CI
- **Production might want quick failure, might not** - we certainly want quick success
- **Go tests take only a few seconds** - this is the benchmark for other languages

### Automated Testing Only
The library either fully works or it doesn't - there are no partial states:
- **If automated tests pass**: The library fully works on that cloud provider
- **If automated tests fail**: The library doesn't work and needs to be fixed
- **No manual validation needed**: Automated tests are the definitive measure

### Test Environment Logic
The critical testing pattern (implemented in Go, must be replicated in other languages):

```python
except s2iam.NoCloudProviderDetectedError:
    # If S2IAM_TEST_CLOUD_PROVIDER is set, fail instead of skip 
    if os.environ.get("S2IAM_TEST_CLOUD_PROVIDER") or os.environ.get("S2IAM_TEST_ASSUME_ROLE"):
        pytest.fail("Cloud provider detection failed - expected to detect provider in test environment")
    pytest.skip("No cloud provider detected - not running in cloud environment")
```

**Why this matters:** Tests should only skip when no cloud provider is expected. When environment variables indicate a cloud provider should be detected, tests must fail if detection fails.

## Real Cloud Testing

### CI/CD Cloud Testing
See `.github/workflows/cloud_provider.yml` for the official CI approach:
- Tests run on actual AWS EC2, GCP Compute Engine, and Azure VMs
- Uses self-hosted runners in real cloud environments
- Tests both Go and Python implementations
- Generates coverage reports for all environments

### Environment Variables for Cloud Testing

Environment selection (exactly one will be set for cloud tests):

- `S2IAM_TEST_CLOUD_PROVIDER`: Set to `aws`/`gcp`/`azure` to indicate cloud tests should run and succeed
- `S2IAM_TEST_ASSUME_ROLE`: Set to test role assumption functionality (e.g., `arn:aws:iam::503396375767:role/NoPermissionsRole`)
  Implies S2IAM_TEST_CLOUD_PROVIDER behavior too.
- `S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE`: Set to `aws`/`gcp`/`azure` to indicate cloud should be detected but no role is available

Local development and no-cloud-CI have no selection variable set. No-cloud-CI is actually Azure w/o a role.

Every test needs to be have correct expectations and/or skips based on the environment selection
variables.

Extra:

- `S2IAM_DEBUGGING`: Set to `true` for verbose test output

Generally speaking, don't use "-v" when running tests: if the test fails it will give verbose
output and if it passes you don't need the detail.

## Command Execution Guidelines

### Terminal Environment Issue and Workaround
After reading this file, try `echo "start" && sleep 3 && echo "done"`. If it does not work, then use the following workaround:

**Solution**: Use `tee` redirection and queue up a command to read the output (human will approve when output is ready)

```bash
# Start command with tee so both agent and human can see output
ssh gcptest2 "cd path && test_command" 2>&1 | tee test_output.log

# Then run: "cat test_output.log"
# Human will approve the cat command when the output is ready
# Agent can then read the full log file for results
```

Use the same output file name (test_output.log) every time so that you don't litter the directory.

## Library Quality Standards

### Non-Negotiable Requirements
- **The Go libraries work. Other language libraries must work too.**
- **Real cloud provider detection must work** - not just mocked tests
- **Performance must match Go implementation** (tests complete in seconds)
- **API compatibility** - users should have similar experience across languages

### Success Criteria for New Language Implementations
1. ✅ All local unit tests pass
2. ✅ Integration tests pass with test server
3. ✅ **Most Important:** Real cloud provider tests pass on AWS/GCP/Azure VMs
4. ✅ Test execution time comparable to Go (seconds, not minutes)
5. ✅ Convenience API functions work as expected

## Working with This Codebase

### Understanding Test Results
- **Skipped tests** in local environment are expected (no cloud metadata available)
- **Failed tests** when `S2IAM_TEST_CLOUD_PROVIDER` is set indicate real problems
- **If automated tests pass, the library fully works. If they fail, it doesn't.**
- **Only pass/fail matters** - either it works completely on real cloud providers or it doesn't

### Common Debugging Patterns
- Check cloud metadata service availability: `curl http://169.254.169.254/`
- Verify environment variables are set correctly in test environments
- Compare test behavior between Go (working) and other language implementations
- Use `S2IAM_DEBUGGING=true` for verbose output

### File Organization
- `go/`: Reference implementation (working standard)
- `python/`: Secondary implementation (goal: match Go functionality)
- `.github/workflows/cloud_provider.yml`: CI testing on real cloud providers

### Errors
- go errors should be tested with errors.Is(). String matching is only okay for external system errors.

## Backawards compatibility

There are no current users of this library. No users of the production server. 
Breaking changes are allowed.

## Key Principles

1. **Real cloud provider functionality is the only thing that matters**
2. **Go implementation is the gold standard** - other languages must match it
3. **Fast test execution** - seconds not minutes
4. **Simple user API** - convenience functions are what users actually use
5. **Proper test failure behavior** - fail fast when cloud detection should work but doesn't
