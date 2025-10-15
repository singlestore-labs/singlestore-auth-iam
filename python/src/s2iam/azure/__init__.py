"""
Microsoft Azure cloud provider client implementation.
"""

import asyncio
import base64
import json
import os
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
        """Detect if running on Azure (full phase, reliability-focused)."""
        if self._detected:
            return

        # Managed identity endpoints can throttle (429). Bounded exponential retries here provide
        # reliable classification (detected-with-identity vs detected-no-identity) without masking
        # genuine absence of Azure signals. Other providers avoid retries to stay fast.
        max_attempts_env = os.environ.get("S2IAM_AZURE_MI_RETRIES", "6")
        base_backoff_ms_env = os.environ.get("S2IAM_AZURE_MI_BACKOFF_MS", "50")
        try:
            max_attempts = max(1, min(20, int(max_attempts_env)))
        except ValueError:
            max_attempts = 6
        try:
            base_backoff_ms = max(1, min(5000, int(base_backoff_ms_env)))
        except ValueError:
            base_backoff_ms = 50

        # Step 1: Probe metadata to establish Azure environment.
        metadata_ok = False
        for i in range(3):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=1)) as session:
                    async with session.get(
                        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                        headers={"Metadata": "true"},
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            if isinstance(data, dict) and data.get("compute"):
                                metadata_ok = True
                                break
                        else:
                            self._log(f"Metadata probe status {response.status} (attempt {i+1}/3)")
            except Exception as e:  # noqa: BLE001
                self._log(f"Metadata probe failed attempt {i+1}/3: {e}")
            await asyncio.sleep(0.05 * (i + 1))

        if not metadata_ok:
            # Fallback: quick DefaultAzureCredential check (Functions / special environments)
            try:
                from azure.identity import DefaultAzureCredential

                cred = DefaultAzureCredential()
                loop = asyncio.get_event_loop()
                token = await loop.run_in_executor(
                    None, lambda: cred.get_token("https://management.azure.com/.default")
                )
                if token:
                    self._detected = True
                    self._log("Detected Azure via DefaultAzureCredential fallback")
                    return
            except Exception as e:  # noqa: BLE001
                self._log(f"DefaultAzureCredential fallback failed: {e}")
            raise Exception("Azure provider not detected")

        # Step 2: Managed identity token attempts (429-aware) for identity availability.
        misclassified = False
        last_error: Optional[str] = None
        for attempt in range(1, max_attempts + 1):  # retries only for Azure MI
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as session:
                    async with session.get(
                        "http://169.254.169.254/metadata/identity/oauth2/token",
                        params={
                            "api-version": "2018-02-01",
                            "resource": "https://management.azure.com/",
                        },
                        headers={"Metadata": "true"},
                    ) as resp:
                        if resp.status == 200:
                            self._detected = True
                            self._log(f"Managed identity token acquired (attempt {attempt}/{max_attempts})")
                            return
                        body_text = await resp.text()
                        if resp.status in (400, 404):
                            misclassified = True
                            last_error = f"identity-missing status={resp.status} body={body_text[:120]}"
                            break
                        if resp.status == 429:
                            last_error = f"throttled 429 body={body_text[:120]}"
                        else:
                            last_error = f"status={resp.status} body={body_text[:120]}"
            except Exception as e:  # noqa: BLE001
                last_error = f"exception={e}"

            if attempt < max_attempts:
                delay = (base_backoff_ms / 1000.0) * (2 ** (attempt - 1))
                delay = min(delay, 3.0)
                await asyncio.sleep(delay)

        if misclassified:
            self._detected = True
            self._log(
                (
                    "Azure environment detected but no managed identity available "
                    f"({last_error}); classification=detected-no-identity"
                )
            )
            return
        if last_error:
            self._detected = True
            self._log(f"Azure detected via metadata but managed identity unavailable after retries ({last_error})")
            return
        if not self._detected:
            raise Exception("Azure provider not detected (unexpected state)")

    async def fast_detect(self) -> None:
        """Fast detection: env/file only, no network."""
        if os.environ.get("AZURE_FEDERATED_TOKEN_FILE") and os.path.isfile(os.environ["AZURE_FEDERATED_TOKEN_FILE"]):
            self._detected = True
            self._log("FastDetect: federated token file present")
            return
        if os.environ.get("AZURE_CLIENT_ID") and os.environ.get("AZURE_TENANT_ID"):
            self._detected = True
            self._log("FastDetect: client+tenant IDs present")
            return
        for var in ("AZURE_ENV", "AZURE_CLIENT_ID", "MSI_ENDPOINT", "IDENTITY_ENDPOINT"):
            if os.environ.get(var):
                self._detected = True
                self._log(f"FastDetect: env var {var} present")
                return
        raise Exception("FastDetect: no Azure indicators")

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
        """Get token from Azure managed identity endpoint with bounded exponential backoff.

        Retry policy rationale:
        - 429 (throttling) and transient 5xx responses are retriable per Azure MSI guidance.
        - 400/404 (e.g. identity not configured) are treated as hard failures (no retries) so we surface
          absence quickly without extending detection / header acquisition latency.
        - Network exceptions (connection reset, timeout) are treated as transient and retried.
        - Default attempts: 6 (≈ < 3.2s worst-case added latency with 50ms base, capped delay 1.6s) mirroring
          detect() logic. Environment overrides respected: S2IAM_AZURE_MI_RETRIES / S2IAM_AZURE_MI_BACKOFF_MS.

        This function is on the identity acquisition path (after successful provider detection) and
        therefore can afford limited retries for robustness without materially impacting overall
        provider classification speed (classification already done)."""
        url = "http://169.254.169.254/metadata/identity/oauth2/token"
        params = {"api-version": "2018-02-01", "resource": resource}
        if client_id:
            params["client_id"] = client_id

        # Read retry configuration (reuse detection env vars for consistency)
        max_attempts_env = os.environ.get("S2IAM_AZURE_MI_RETRIES", "6")
        base_backoff_ms_env = os.environ.get("S2IAM_AZURE_MI_BACKOFF_MS", "50")
        try:
            max_attempts = max(1, min(20, int(max_attempts_env)))
        except ValueError:
            max_attempts = 6
        try:
            base_backoff_ms = max(1, min(5000, int(base_backoff_ms_env)))
        except ValueError:
            base_backoff_ms = 50

        last_error: Optional[str] = None
        for attempt in range(1, max_attempts + 1):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as session:
                    async with session.get(url, params=params, headers={"Metadata": "true"}) as response:
                        if response.status == 200:
                            data = await response.json()
                            token = {str(k): str(v) for k, v in data.items() if isinstance(k, str)}
                            if self._logger:
                                self._logger.log(
                                    f"Azure: Managed identity token success (attempt {attempt}/{max_attempts})"
                                )
                            return token
                        body_text = await response.text()
                        # Hard non-retriable statuses (identity absent / misconfiguration)
                        if response.status in (400, 404):
                            raise Exception(
                                f"Failed to get managed identity token: {response.status} - {body_text[:180]}"
                            )
                        # Retriable statuses
                        if response.status == 429 or 500 <= response.status < 600:
                            last_error = f"status={response.status} body={body_text[:180]}"
                            if self._logger:
                                self._logger.log(
                                    "Azure: Managed identity token transient error "
                                    f"(attempt {attempt}/{max_attempts}) {last_error}"
                                )
                        else:
                            # Non-retriable other status; surface immediately
                            raise Exception(
                                f"Failed to get managed identity token: {response.status} - {body_text[:180]}"
                            )
            except Exception as e:  # noqa: BLE001
                # Network or other transient exception; decide to retry unless last attempt
                last_error = f"exception={e}"
                if attempt == max_attempts:
                    raise Exception(f"Failed to get managed identity token after retries: {last_error}")
                if self._logger:
                    self._logger.log(f"Azure: Managed identity token exception (attempt {attempt}/{max_attempts}) {e}")

            # Backoff before next attempt if not returned / raised
            if attempt < max_attempts:
                delay = (base_backoff_ms / 1000.0) * (2 ** (attempt - 1))
                # Cap single delay to 1.6s here (shorter than detect() cap) to bound identity latency
                delay = min(delay, 1.6)
                await asyncio.sleep(delay)

        # If loop exits without returning, raise aggregated last error
        raise Exception(
            f"Failed to get managed identity token after {max_attempts} attempts: {last_error or 'unknown-error'}"
        )

    async def _get_instance_metadata(self) -> dict[str, Any]:
        """Get Azure instance metadata."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "http://169.254.169.254/metadata/instance?api-version=2018-02-01",
                    headers={"Metadata": "true"},
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data if isinstance(data, dict) else {}
                    else:
                        return {}
        except Exception as e:
            self._log(f"Failed to get instance metadata: {e}")
            return {}


def new_client(logger: Optional[Logger] = None) -> CloudProviderClient:
    """Create a new Azure client."""
    return AzureClient(logger)
