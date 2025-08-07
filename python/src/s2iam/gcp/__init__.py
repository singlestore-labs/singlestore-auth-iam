"""
Google Cloud Platform provider client implementation.
"""

import asyncio
import os
import urllib.request
import urllib.error
from typing import Optional
import socket

import aiohttp

from ..models import (
    CloudIdentity,
    CloudProviderClient,
    CloudProviderType,
    Logger,
    ProviderIdentityUnavailable,
    ProviderNotDetected,
)


class GCPClient(CloudProviderClient):
    """GCP implementation of CloudProviderClient."""

    def __init__(self, logger: Optional[Logger] = None):
        self._logger = logger
        self._detected = False
        self._service_account_email: Optional[str] = None
        self._identity: Optional[CloudIdentity] = None

    def _log(self, message: str) -> None:
        """Log a message if logger is available."""
        if self._logger:
            self._logger.log(f"GCP: {message}")

    async def detect(self) -> None:
        """Detect if running on GCP (matches Go implementation)."""
        self._log("Starting GCP detection")

        # Fast path: Check if GCE_METADATA_HOST environment variable is set
        if os.environ.get("GCE_METADATA_HOST"):
            self._log("Found GCE_METADATA_HOST environment variable")
            # When env var is set, we need to verify identity access (strict check)
            try:
                await self._verify_metadata_access()
                self._log("GCP identity metadata access verified")
                self._detected = True
                return
            except Exception:
                self._log("Metadata service available but no identity access")
                raise ProviderIdentityUnavailable(
                    "GCP metadata available but no identity access"
                )

        # Try to access GCP metadata service directly
        self._log("Trying metadata service")
        try:
            # Use urllib with explicit timeout (matches Go's http.Client{Timeout: 3 * time.Second})
            def sync_check():
                req = urllib.request.Request(
                    "http://metadata.google.internal/computeMetadata/v1/instance/id",
                    headers={"Metadata-Flavor": "Google"}
                )
                # Set socket timeout to match Go implementation
                socket.setdefaulttimeout(3.0)
                try:
                    with urllib.request.urlopen(req, timeout=3.0) as response:
                        if response.status == 200:
                            return True
                        else:
                            raise Exception(f"Metadata service returned status {response.status}")
                finally:
                    socket.setdefaulttimeout(None)  # Reset to default
            
            # Run sync operation in executor to avoid blocking event loop
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, sync_check)
            
            self._log("Successfully detected GCP environment")
            self._detected = True
            return
            
        except Exception as e:
            error_msg = str(e) if str(e) else f"{type(e).__name__}"
            self._log(f"Metadata service error: {error_msg}")
            raise Exception(
                f"Not running on GCP: metadata service unavailable (no GCE_METADATA_HOST env var and cannot reach metadata.google.internal): {error_msg}"
            )

        raise Exception(
            "Not running on GCP: no environment variable, metadata service, or default credentials detected"
        )

    async def _verify_metadata_access(self) -> None:
        """Verify we can access identity-related metadata."""
        try:
            # Use asyncio.wait_for with explicit timeout (matches Go's pattern)
            async def check_identity_access():
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=2)
                ) as session:
                    async with session.get(
                        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/",
                        headers={"Metadata-Flavor": "Google"},
                    ) as response:
                        if response.status != 200:
                            raise ProviderIdentityUnavailable(
                                f"GCP metadata available but no identity access (status {response.status})"
                            )
            
            # Use wait_for with 2 second timeout (matches Go implementation)
            await asyncio.wait_for(check_identity_access(), timeout=2.0)
            
        except asyncio.TimeoutError:
            raise ProviderIdentityUnavailable(
                "Cannot access GCP identity metadata: timeout"
            )
        except aiohttp.ClientError as e:
            raise ProviderIdentityUnavailable(
                f"Cannot access GCP identity metadata: {e}"
            )
        except Exception as e:
            error_msg = str(e) if str(e) else f"{type(e).__name__}"
            raise ProviderIdentityUnavailable(
                f"Cannot access GCP identity metadata: {error_msg}"
            )

    def get_type(self) -> CloudProviderType:
        """Return GCP provider type."""
        return CloudProviderType.GCP

    def assume_role(self, role_identifier: str) -> "GCPClient":
        """Create a new client with assumed service account."""
        new_client = GCPClient(self._logger)
        new_client._detected = self._detected
        new_client._service_account_email = role_identifier
        return new_client

    async def get_identity_headers(
        self, additional_params: Optional[dict[str, str]] = None
    ) -> tuple[dict[str, str], CloudIdentity]:
        """Get GCP identity headers."""
        if not self._detected:
            raise ProviderNotDetected(
                "GCP provider not detected, call detect() first"
            )

        audience = (
            additional_params.get("audience", "https://authsvc.singlestore.com")
            if additional_params
            else "https://authsvc.singlestore.com"
        )

        try:
            if self._service_account_email:
                # Get token through impersonation
                token = await self._get_impersonated_token(audience)
                project_info = await self._get_project_info()

                # Use email address directly as identifier (matches Go implementation)
                identity = CloudIdentity(
                    provider=CloudProviderType.GCP,
                    identifier=self._service_account_email,
                    account_id=self._service_account_email,
                    region=await self._get_zone(),
                    resource_type="gcp-service-account",
                )
            else:
                # Get default identity token
                token = await self._get_identity_token(audience)
                project_info = await self._get_project_info()
                service_account = await self._get_service_account()

                # Use email address directly as identifier (matches Go implementation)
                identity = CloudIdentity(
                    provider=CloudProviderType.GCP,
                    identifier=service_account,
                    account_id=service_account,
                    region=await self._get_zone(),
                    resource_type="gcp-compute-instance",
                )

            headers = {
                "Authorization": f"Bearer {token}",
            }

            self._log(f"Generated headers for identity: {identity.identifier}")
            return headers, identity

        except Exception as e:
            self._log(f"Failed to get identity headers: {e}")
            raise ProviderIdentityUnavailable(f"Failed to get GCP identity: {e}")

    async def _get_identity_token(self, audience: str) -> str:
        """Get identity token from metadata service."""
        url = f"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={audience}&format=full"

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers={"Metadata-Flavor": "Google"}
            ) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    raise Exception(f"Failed to get identity token: {response.status}")

    async def _get_impersonated_token(self, audience: str) -> str:
        """Get token through service account impersonation."""
        # First get our own token for authentication
        self_token = await self._get_identity_token(
            "https://iamcredentials.googleapis.com/"
        )

        # Request impersonated token
        url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{self._service_account_email}:generateIdToken"

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers={
                    "Authorization": f"Bearer {self_token}",
                    "Content-Type": "application/json",
                },
                json={"audience": audience},
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data["token"]
                else:
                    text = await response.text()
                    raise Exception(
                        f"Impersonation failed with status {response.status}: {text}"
                    )

    async def _get_project_info(self) -> dict[str, str]:
        """Get project information from metadata."""
        info = {}

        async with aiohttp.ClientSession() as session:
            # Get project ID
            try:
                async with session.get(
                    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                    headers={"Metadata-Flavor": "Google"},
                ) as response:
                    if response.status == 200:
                        info["projectId"] = await response.text()
            except Exception as e:
                self._log(f"Failed to get project ID: {e}")

            # Get project number
            try:
                async with session.get(
                    "http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id",
                    headers={"Metadata-Flavor": "Google"},
                ) as response:
                    if response.status == 200:
                        info["projectNumber"] = await response.text()
            except Exception as e:
                self._log(f"Failed to get project number: {e}")

        return info

    async def _get_service_account(self) -> str:
        """Get default service account email."""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
                headers={"Metadata-Flavor": "Google"},
            ) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    return "unknown"

    async def _get_zone(self) -> str:
        """Get zone information."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "http://metadata.google.internal/computeMetadata/v1/instance/zone",
                    headers={"Metadata-Flavor": "Google"},
                ) as response:
                    if response.status == 200:
                        zone_path = await response.text()
                        # Extract zone from path like "projects/123/zones/us-central1-a"
                        return (
                            zone_path.split("/")[-1] if "/" in zone_path else zone_path
                        )
        except Exception as e:
            self._log(f"Failed to get zone: {e}")

        return ""


def new_client(logger: Optional[Logger] = None) -> CloudProviderClient:
    """Create a new GCP client."""
    return GCPClient(logger)
