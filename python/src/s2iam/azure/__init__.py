"""
Microsoft Azure cloud provider client implementation.
"""

import asyncio
import os
import base64
import json
from typing import Any, Optional

import aiohttp

from ..models import (
    CloudIdentity,
    CloudProviderClient,
    CloudProviderType,
    Logger,
    ProviderIdentityUnavailable,
    ProviderNotDetected,
)


class AzureClient(CloudProviderClient):
    """Azure implementation of CloudProviderClient."""

    def __init__(self, logger: Optional[Logger] = None):
        self._logger = logger
        self._detected = False
        self._managed_identity_id: Optional[str] = None
        self._identity: Optional[CloudIdentity] = None
        self._assume_role_requested = False

    def _log(self, message: str) -> None:
        """Log a message if logger is available."""
        if self._logger:
            self._logger.log(f"Azure: {message}")

    async def detect(self) -> None:
        """Detect if running on Azure (matches Go implementation)."""
        self._log("Starting Azure detection")

        # Fast path: Check all relevant Azure environment variables
        env_vars = [
            "AZURE_ENV",
            "AZURE_CLIENT_ID",
            "MSI_ENDPOINT",
            "IDENTITY_ENDPOINT",
        ]
        for var in env_vars:
            if os.environ.get(var):
                self._log(f"Found Azure environment variable: {var}")
                self._detected = True
                return

        # Try to access Azure metadata service
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
                async with session.get(
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                    headers={"Metadata": "true"},
                ) as response:
                    if response.status == 200:
                        instance_data = await response.json()
                        if instance_data.get("compute"):
                            self._log("Successfully accessed Azure metadata service")
                            self._detected = True
                            return
                    else:
                        self._log(f"Azure metadata service returned status {response.status}")
        except Exception as e:
            self._log(f"Failed to access Azure metadata service: {e}")

        # If metadata service is available, verify managed identity access
        if self._detected:
            try:
                await self._test_managed_identity_token()
                self._log("Verified managed identity access")
                return
            except Exception as e:
                self._log(f"Azure metadata available but managed identity failed: {e}")
                # Reset detection since managed identity is not available
                self._detected = False

        # Try Azure default credentials as fallback
        try:
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential()
            loop = asyncio.get_event_loop()
            token = await loop.run_in_executor(
                None,
                lambda: credential.get_token("https://management.azure.com/.default"),
            )
            if token:
                self._log("Found Azure default credentials")
                self._detected = True
                return
        except Exception as e:
            self._log(f"No Azure default credentials: {e}")

        raise Exception(
            "Not running on Azure: no environment variable, metadata service, or default credentials detected"
        )

    async def _test_managed_identity_token(self) -> None:
        """Test if managed identity token is available (similar to Go implementation)."""
        try:
            # Test token request to management API with very short timeout for fast failure
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=1)  # 1 second timeout for fast CI
            ) as session:
                async with session.get(
                    "http://169.254.169.254/metadata/identity/oauth2/token",
                    params={
                        "api-version": "2018-02-01",
                        "resource": "https://management.azure.com/",
                    },
                    headers={"Metadata": "true"},
                ) as response:
                    if response.status == 200:
                        # Success - managed identity is available
                        return
                    elif response.status == 400:
                        # Check for "Identity not found" error like Go implementation
                        try:
                            error_data = await response.json()
                            if error_data.get("error") == "invalid_request" and "Identity not found" in error_data.get(
                                "error_description", ""
                            ):
                                raise Exception("No managed identity configured on this Azure VM")
                        except Exception:
                            # If we can't parse the error, still fail
                            pass

                    # Any other error status
                    text = await response.text()
                    raise Exception(f"Managed identity test failed: {response.status} - {text}")

        except aiohttp.ClientError as e:
            # Network errors (timeout, connection refused, etc.)
            self._log(f"Managed identity network error: {e}")
            raise Exception(f"Cannot reach managed identity endpoint: {e}")
        except Exception as e:
            self._log(f"Managed identity test failed: {e}")
            raise

    async def _verify_identity_access(self) -> None:
        """Verify we can access Azure identity services."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as session:
                async with session.get(
                    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",  # noqa: E501
                    headers={"Metadata": "true"},
                ) as response:
                    if response.status != 200:
                        raise ProviderIdentityUnavailable("Azure metadata available but no identity access")
        except aiohttp.ClientError as e:
            raise ProviderIdentityUnavailable(f"Cannot access Azure identity metadata: {e}")

    def get_type(self) -> CloudProviderType:
        """Return Azure provider type."""
        return CloudProviderType.AZURE

    def assume_role(self, role_identifier: str) -> "AzureClient":
        """Create a new client with assumed managed identity."""
        new_client = AzureClient(self._logger)
        new_client._detected = self._detected
        new_client._managed_identity_id = role_identifier
        new_client._assume_role_requested = True
        return new_client

    async def get_identity_headers(
        self, additional_params: Optional[dict[str, str]] = None
    ) -> tuple[dict[str, str], CloudIdentity]:
        """Get Azure identity headers."""
        if not self._detected:
            raise ProviderNotDetected("Azure provider not detected, call detect() first")

        try:
            # Get access token for Azure management API
            if self._managed_identity_id:
                # Use specific managed identity
                token_data = await self._get_managed_identity_token(
                    "https://management.azure.com/", self._managed_identity_id
                )
            else:
                # Use default identity
                token_data = await self._get_managed_identity_token("https://management.azure.com/")

            # Get instance metadata (unsigned) - we only use subscription/resource group names for
            # informational additional claims; REGION MUST COME FROM SIGNED TOKEN CLAIMS ONLY.
            instance_metadata = await self._get_instance_metadata()

            # Extract principal ID and claims from token
            principal_id, token_claims = await self._extract_principal_id_and_claims(token_data["access_token"])
            subscription_id = instance_metadata.get("compute", {}).get("subscriptionId", "")

            # Derive region strictly from signed token (xms_mirid) to match Go verifier logic.
            # We DO NOT trust the metadata 'location' field for region equality because it is not
            # cryptographically bound to the managed identity token and the server only sees the token.
            region = ""
            mirid = token_claims.get("xms_mirid", "")
            if isinstance(mirid, str) and mirid:
                parts = mirid.split("/")
                for i in range(len(parts) - 1):
                    if parts[i] == "resourceGroups" and i + 1 < len(parts):
                        rg_name = parts[i + 1]
                        rg_parts = rg_name.split("-")
                        if len(rg_parts) > 2:
                            region = rg_parts[-2] + "-" + rg_parts[-1]
                            break

            # Build identity with region derived only from signed data (may be empty)
            identity = CloudIdentity(
                provider=CloudProviderType.AZURE,
                identifier=principal_id,
                account_id=subscription_id,
                region=region,
                resource_type="azure-managed-identity",
            )

            # Record unsigned metadata location for observability without asserting equality
            metadata_location = instance_metadata.get("compute", {}).get("location", "")
            if metadata_location and metadata_location != region:
                identity.additional_claims["metadata_location"] = metadata_location

            headers = {
                "X-Cloud-Provider": "azure",
                "Authorization": f"Bearer {token_data['access_token']}",
                "X-Azure-Subscription-ID": subscription_id,
                "X-Azure-Resource-Group": instance_metadata.get("compute", {}).get("resourceGroupName", ""),
            }

            self._log(f"Generated headers for identity: {identity.identifier}")
            return headers, identity

        except Exception as e:
            self._log(f"Failed to get identity headers: {e}")
            raise ProviderIdentityUnavailable(f"Failed to get Azure identity: {e}")

    async def _extract_principal_id_and_claims(self, access_token: str) -> tuple[str, dict[str, Any]]:
        """Extract principal ID and full claims from JWT (signed data only)."""
        try:
            parts = access_token.split(".")
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")
            payload = parts[1]
            payload += "=" * (4 - len(payload) % 4)
            decoded_payload = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded_payload)

            if "oid" in claims:
                return claims["oid"], claims
            if "sub" in claims:
                return claims["sub"], claims
            if "appid" in claims:
                return claims["appid"], claims
            raise ValueError("Principal ID not found in Azure token")
        except Exception as e:
            self._log(f"Failed to extract principal ID from token: {e}")
            return "unknown", {}

    async def _get_managed_identity_token(self, resource: str, client_id: Optional[str] = None) -> dict[str, str]:
        """Get token from Azure managed identity endpoint."""
        url = "http://169.254.169.254/metadata/identity/oauth2/token"
        params = {"api-version": "2018-02-01", "resource": resource}

        if client_id:
            params["client_id"] = client_id

        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, headers={"Metadata": "true"}) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    text = await response.text()
                    raise Exception(f"Failed to get managed identity token: {response.status} - {text}")

    async def _get_instance_metadata(self) -> dict[str, Any]:
        """Get Azure instance metadata."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "http://169.254.169.254/metadata/instance?api-version=2018-02-01",
                    headers={"Metadata": "true"},
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {}
        except Exception as e:
            self._log(f"Failed to get instance metadata: {e}")
            return {}


def new_client(logger: Optional[Logger] = None) -> CloudProviderClient:
    """Create a new Azure client."""
    return AzureClient(logger)
