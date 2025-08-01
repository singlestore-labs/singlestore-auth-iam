# Test configuration file
"""
Pytest configuration for s2iam tests.
"""

import os

import pytest


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "aws: marks tests as AWS-specific")
    config.addinivalue_line("markers", "gcp: marks tests as GCP-specific")
    config.addinivalue_line("markers", "azure: marks tests as Azure-specific")
    config.addinivalue_line(
        "markers", "cloud_validation: marks tests as automated cloud validation tests"
    )
    config.addinivalue_line(
        "markers", "requires_cloud: marks tests that require real cloud environment"
    )


def pytest_collection_modifyitems(config, items):
    """Automatically mark integration tests and skip cloud-dependent tests only when necessary."""
    for item in items:
        # Mark integration tests
        if "test_integration" in item.nodeid or "test_cloud_validation" in item.nodeid:
            item.add_marker(pytest.mark.integration)

        # Mark cloud validation tests
        if "test_cloud_validation" in item.nodeid:
            item.add_marker(pytest.mark.cloud_validation)

        # Only skip tests that explicitly require cloud environments in CI without cloud access
        # Most tests should work with proper error handling when no cloud provider is detected
        if hasattr(item, "get_closest_marker"):
            # Only skip tests explicitly marked as requiring cloud
            if item.get_closest_marker("requires_cloud"):
                # Only skip if we're clearly in a CI environment without cloud access
                if os.environ.get("GITHUB_ACTIONS") and not _is_any_cloud_environment():
                    item.add_marker(
                        pytest.mark.skip(
                            reason="Test explicitly requires cloud environment"
                        )
                    )

            # Provider-specific tests should only skip if we're in CI and not in the right cloud
            if item.get_closest_marker("aws") and os.environ.get("GITHUB_ACTIONS"):
                if not _check_aws_metadata():
                    item.add_marker(
                        pytest.mark.skip(reason="Not running in AWS environment")
                    )

            if item.get_closest_marker("gcp") and os.environ.get("GITHUB_ACTIONS"):
                if not _check_gcp_metadata():
                    item.add_marker(
                        pytest.mark.skip(reason="Not running in GCP environment")
                    )

            if item.get_closest_marker("azure") and os.environ.get("GITHUB_ACTIONS"):
                if not _check_azure_metadata():
                    item.add_marker(
                        pytest.mark.skip(reason="Not running in Azure environment")
                    )


def _is_any_cloud_environment():
    """Check if running in any cloud environment using the same logic as the library."""
    # Use the actual s2iam library to detect providers
    import asyncio

    import s2iam

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Already in an async context, can't use asyncio.run
            # Fall back to environment variable check
            env_indicators = [
                # AWS
                "AWS_REGION",
                "AWS_DEFAULT_REGION",
                "AWS_EXECUTION_ENV",
                # GCP
                "GOOGLE_CLOUD_PROJECT",
                "GCP_PROJECT",
                "GCE_METADATA_HOST",
                # Azure
                "AZURE_CLIENT_ID",
                "MSI_ENDPOINT",
                "IDENTITY_ENDPOINT",
            ]

            if any(os.environ.get(indicator) for indicator in env_indicators):
                return True

            # Check metadata services as fallback
            return (
                _check_aws_metadata()
                or _check_gcp_metadata()
                or _check_azure_metadata()
            )
    except RuntimeError:
        # No event loop, we can create one
        pass

    try:
        # Try to detect provider using s2iam
        async def detect():
            try:
                provider = await s2iam.detect_provider(timeout=3.0)
                return provider is not None
            except Exception:
                return False

        return asyncio.run(detect())
    except Exception:
        # Fall back to metadata checks if s2iam detection fails
        return _check_aws_metadata() or _check_gcp_metadata() or _check_azure_metadata()


def _check_aws_metadata():
    """Check if AWS can be detected using s2iam library.

    Uses the actual s2iam AWS client to ensure detection logic matches
    what the library itself uses. Falls back to direct metadata checks
    if the library detection fails (e.g., due to missing dependencies).
    """
    try:
        import asyncio

        import s2iam.aws

        async def check():
            try:
                client = s2iam.aws.new_client()
                await client.detect()
                return True
            except Exception:
                return False

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Fall back to metadata check if in async context
                import urllib.error
                import urllib.request

                # Try to get token first (IMDSv2)
                req = urllib.request.Request(
                    "http://169.254.169.254/latest/api/token", method="PUT"
                )
                req.add_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")

                with urllib.request.urlopen(req, timeout=2) as response:
                    if response.status == 200:
                        return True
        except (urllib.error.URLError, OSError, Exception):
            pass

        try:
            return asyncio.run(check())
        except Exception:
            return False
    except Exception:
        # Final fallback to simple metadata check
        try:
            import urllib.error
            import urllib.request

            # Try to get token first (IMDSv2)
            req = urllib.request.Request(
                "http://169.254.169.254/latest/api/token", method="PUT"
            )
            req.add_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")

            with urllib.request.urlopen(req, timeout=2) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError, Exception):
            pass

        return False


def _check_gcp_metadata():
    """Check if GCP can be detected using s2iam library."""
    try:
        import asyncio

        import s2iam.gcp

        async def check():
            try:
                client = s2iam.gcp.new_client()
                await client.detect()
                return True
            except Exception:
                return False

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Fall back to metadata check if in async context
                import urllib.error
                import urllib.request

                req = urllib.request.Request(
                    "http://metadata.google.internal/computeMetadata/v1/instance/id"
                )
                req.add_header("Metadata-Flavor", "Google")

                with urllib.request.urlopen(req, timeout=2) as response:
                    return response.status == 200
        except (urllib.error.URLError, OSError, Exception):
            pass

        try:
            return asyncio.run(check())
        except Exception:
            return False
    except Exception:
        # Final fallback to simple metadata check
        try:
            import urllib.error
            import urllib.request

            req = urllib.request.Request(
                "http://metadata.google.internal/computeMetadata/v1/instance/id"
            )
            req.add_header("Metadata-Flavor", "Google")

            with urllib.request.urlopen(req, timeout=2) as response:
                return response.status == 200
        except (urllib.error.URLError, OSError, Exception):
            pass

        return False


def _check_azure_metadata():
    """Check if Azure can be detected using s2iam library."""
    try:
        import asyncio

        import s2iam.azure

        async def check():
            try:
                client = s2iam.azure.new_client()
                await client.detect()
                return True
            except Exception:
                return False

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Fall back to metadata check if in async context
                import urllib.error
                import urllib.request

                req = urllib.request.Request(
                    "http://169.254.169.254/metadata/instance?api-version=2018-02-01"
                )
                req.add_header("Metadata", "true")

                with urllib.request.urlopen(req, timeout=2) as response:
                    return response.status == 200
        except (urllib.error.URLError, OSError, Exception):
            pass

        try:
            return asyncio.run(check())
        except Exception:
            return False
    except Exception:
        # Final fallback to simple metadata check
        try:
            import urllib.error
            import urllib.request

            req = urllib.request.Request(
                "http://169.254.169.254/metadata/instance?api-version=2018-02-01"
            )
            req.add_header("Metadata", "true")

            with urllib.request.urlopen(req, timeout=2) as response:
                return response.status == 200
        except (urllib.error.URLError, OSError, Exception):
            pass

        return False
