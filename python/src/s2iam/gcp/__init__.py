"""
Google Cloud Platform provider client implementation.
"""

import asyncio
import os
from typing import Any, Optional

import aiohttp
import jwt

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

    def __init__(self, logger: Optional[Logger] = None) -> None:
        self._logger = logger
        self._detected = False
        self._service_account_email: Optional[str] = None
        self._identity: Optional[CloudIdentity] = None

    def _log(self, message: str) -> None:
        """Log a message if logger is available."""
        if self._logger:
            self._logger.log(f"GCP: {message}")

    # Timeouts (kept close to Go defaults for parity)
    GCP_DETECT_IDENTITY_TIMEOUT = 2.0
    GCP_DETECT_METADATA_TIMEOUT = 3.0
    GCP_METADATA_TOKEN_HTTP_TIMEOUT = 5.0
    GCP_IMPERSONATION_HTTP_TIMEOUT = 10.0

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
                raise ProviderIdentityUnavailable("GCP metadata available but no identity access")

        # Try to access GCP metadata service directly (use aiohttp; fallback to IP to avoid DNS issues)
        self._log("Trying metadata service")
        urls = [
            "http://metadata.google.internal/computeMetadata/v1/instance/id",
            "http://169.254.169.254/computeMetadata/v1/instance/id",
        ]
        last_error: Optional[str] = None
        for url in urls:
            try:
                timeout = aiohttp.ClientTimeout(total=self.GCP_DETECT_METADATA_TIMEOUT)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, headers={"Metadata-Flavor": "Google"}) as response:
                        if response.status == 200:
                            self._log("Successfully detected GCP environment")
                            self._detected = True
                            return
                        else:
                            last_error = f"status {response.status}"
                            self._log(f"Metadata service returned {last_error} for {url}")
            except Exception as e:
                last_error = str(e) if str(e) else f"{type(e).__name__}"
                self._log(f"Metadata service error for {url}: {last_error}")

        # If neither URL worked, propagate a clear error
        msg = (
            "Not running on GCP: metadata service unavailable (no GCE_METADATA_HOST env var and "
            "cannot reach metadata endpoints)"
        )
        raise Exception(msg + (f": {last_error}" if last_error else ""))

    async def _verify_metadata_access(self) -> None:
        """Verify we can access identity-related metadata."""
        try:
            # Use asyncio.wait_for with explicit timeout (matches Go's pattern)
            async def check_identity_access() -> None:
                hosts = []
                if os.environ.get("GCE_METADATA_HOST"):
                    hosts.append(os.environ["GCE_METADATA_HOST"])  # e.g., metadata.google.internal or IP
                hosts.extend(
                    [
                        "metadata.google.internal",
                        "169.254.169.254",
                    ]
                )
                last_status = None
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.GCP_DETECT_IDENTITY_TIMEOUT)
                ) as session:
                    for host in hosts:
                        url = f"http://{host}/computeMetadata/v1/instance/service-accounts/default/"
                        try:
                            async with session.get(url, headers={"Metadata-Flavor": "Google"}) as response:
                                if response.status == 200:
                                    return
                                last_status = response.status
                        except Exception:
                            continue
                raise ProviderIdentityUnavailable(
                    "GCP metadata available but no identity access"
                    + (f" (last status {last_status})" if last_status else "")
                )

            # Use wait_for with explicit timeout
            await asyncio.wait_for(check_identity_access(), timeout=self.GCP_DETECT_IDENTITY_TIMEOUT)

        except asyncio.TimeoutError:
            raise ProviderIdentityUnavailable("Cannot access GCP identity metadata: timeout")
        except aiohttp.ClientError as e:
            raise ProviderIdentityUnavailable(f"Cannot access GCP identity metadata: {e}")
        except Exception as e:
            error_msg = str(e) if str(e) else f"{type(e).__name__}"
            raise ProviderIdentityUnavailable(f"Cannot access GCP identity metadata: {error_msg}")

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
            raise ProviderNotDetected("GCP provider not detected, call detect() first")

        audience = (
            additional_params.get("audience", "https://authsvc.singlestore.com")
            if additional_params
            else "https://authsvc.singlestore.com"
        )

        try:
            if self._service_account_email:
                # Get token through impersonation
                token = await self._get_impersonated_token(audience)

                # Parse impersonated token to extract identity information
                identity = await self._extract_identity_from_token(token, self._service_account_email)
            else:
                # Get default identity token
                token = await self._get_identity_token(audience)
                service_account = await self._get_service_account()

                # Parse token to extract identity information (matching Go implementation)
                identity = await self._extract_identity_from_token(token, service_account)

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
        url = f"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={audience}&format=full"  # noqa: E501

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.GCP_METADATA_TOKEN_HTTP_TIMEOUT)
        ) as session:
            async with session.get(url, headers={"Metadata-Flavor": "Google"}) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    raise Exception(f"Failed to get identity token: {response.status}")

    async def _get_impersonated_token(self, audience: str) -> str:
        """Get token through service account impersonation."""
        # First get our own token for authentication
        self_token = await self._get_identity_token("https://iamcredentials.googleapis.com/")

        # Request impersonated token
        url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{self._service_account_email}:generateIdToken"  # noqa: E501

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.GCP_IMPERSONATION_HTTP_TIMEOUT)
        ) as session:
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
                    token_value = data.get("token") if isinstance(data, dict) else None
                    if not isinstance(token_value, str):
                        raise Exception("Impersonation response did not include a string token")
                    return token_value
                else:
                    text = await response.text()
                    raise Exception(f"Impersonation failed with status {response.status}: {text}")

    async def _get_project_info(self) -> dict[str, str]:
        """Get project information from metadata."""
        info = {}

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.GCP_METADATA_TOKEN_HTTP_TIMEOUT)
        ) as session:
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
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.GCP_METADATA_TOKEN_HTTP_TIMEOUT)
        ) as session:
            async with session.get(
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
                headers={"Metadata-Flavor": "Google"},
            ) as response:
                if response.status == 200:
                    text_value = await response.text()
                    return str(text_value)
                else:
                    return "unknown"

    async def _get_zone(self) -> str:
        """Get zone information."""
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.GCP_METADATA_TOKEN_HTTP_TIMEOUT)
            ) as session:
                async with session.get(
                    "http://metadata.google.internal/computeMetadata/v1/instance/zone",
                    headers={"Metadata-Flavor": "Google"},
                ) as response:
                    if response.status == 200:
                        zone_path = await response.text()
                        # Extract zone from path like "projects/123/zones/us-central1-a"
                        return zone_path.split("/")[-1] if "/" in zone_path else zone_path
        except Exception as e:
            self._log(f"Failed to get zone: {e}")

        return ""

    async def _extract_identity_from_token(self, token: str, service_account: str) -> CloudIdentity:
        """Extract identity information from GCP token (matching Go implementation).

        Args:
            token: The GCP identity token
            service_account: The service account email from metadata

        Returns:
            CloudIdentity with correct identifier and account_id
        """
        try:
            # Parse JWT without verification (since we got it from GCP directly)
            claims: dict[str, Any] = jwt.decode(token, options={"verify_signature": False})

            # Get numeric account ID from sub claim (always present)
            account_id = claims.get("sub", "")
            if not account_id:
                raise ValueError("No sub claim found in GCP token")

            # Determine identifier - prefer verified email, fallback to sub
            identifier = account_id  # Default to numeric ID
            if claims.get("email") and claims.get("email_verified", False):
                identifier = claims["email"]
                self._log(f"Using verified email as identifier: {identifier}")
            else:
                self._log(f"Using sub claim as identifier: {identifier}")

            # Extract region from zone if available
            region = ""
            zone = await self._get_zone()
            if zone:
                # Extract region from zone (e.g., us-east4-c -> us-east4)
                parts = zone.split("-")
                if len(parts) >= 3:
                    region = "-".join(parts[:-1])

            return CloudIdentity(
                provider=CloudProviderType.GCP,
                identifier=identifier,
                account_id=account_id,  # This is the numeric sub from JWT
                region=region,
                resource_type="gcp-compute-instance",
            )

        except Exception as e:
            self._log(f"Failed to extract identity from token: {e}")
            # Fallback to service account email for both fields
            return CloudIdentity(
                provider=CloudProviderType.GCP,
                identifier=service_account,
                account_id=service_account,
                region=await self._get_zone(),
                resource_type="gcp-compute-instance",
            )


def new_client(logger: Optional[Logger] = None) -> CloudProviderClient:
    """Create a new GCP client."""
    return GCPClient(logger)
