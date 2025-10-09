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

    async def detect(self) -> None:
        """Detect if running on GCP (full phase)."""
        self._log("Starting GCP detection (full phase)")
        if self._detected:
            return

        # IMPORTANT (future maintainer / future-me): Do NOT add retries here unless you can
        # produce a reproducible, provider-side behavioral change that: (a) manifests as
        # a transient failure on the very first metadata probe AND (b) becomes a success
        # within <1s WITHOUT any configuration / environment change. Historical context:
        # A GCP detection timeout once occurred and a retry loop was briefly added. Root
        # cause analysis showed the failure was due to logic (raising before queue publish),
        # not actual transient unavailability of the metadata endpoint. Adding retries
        # masked the underlying bug and only injected latency + flakiness surface area.
        #
        # Why single attempt is correct for GCP:
        # 1. GCP metadata service is either immediately reachable or definitively absent.
        #    (Contrast: Azure IMDS managed identity can 429/throttle legitimately, hence
        #    bounded exponential retry ONLY on Azure identity acquisition.)
        # 2. Fast failing keeps cross‑provider race tight and test suite duration low.
        # 3. Retries make real configuration errors (firewall / network namespace / wrong
        #    cloud) slower to surface and harder to differentiate from genuine detection.
        # 4. Every added retry path previously obscured a logic bug rather than fixing a
        #    platform instability.
        #
        # If you believe you need a retry, first capture:
        #   - exact wall clock timings
        #   - packet trace or tcpdump showing SYN/SYN-ACK delay OR DNS resolution latency
        #   - evidence that a second attempt (without any delay you inserted) would have
        #     succeeded (e.g., manual immediate second curl succeeds while first failed)
        # and document that evidence in a linked issue. Without that, DO NOT ADD RETRIES.
        #
        # This comment is intentionally dry and procedural to discourage casual edits.
        # Removing it or ignoring its instructions without evidence is a regression.
        # Single bounded metadata probe (no retry). GCP metadata is either reachable promptly
        # or not present; retries add latency and can mask a real negative signal. We intentionally
        # avoid the hostname form to remove DNS as a variable; the hostname resolves to this
        # link-local address in normal GCE environments. If future evidence shows hostname-only
        # success patterns, we can re-evaluate.
        self._log("Trying metadata service (link-local IP, single attempt)")

        loop = asyncio.get_event_loop()
        start = loop.time()
        metadata_url = "http://169.254.169.254/computeMetadata/v1/instance/id"
        per_attempt_timeout = 3  # seconds (aiohttp total timeout)
        env_hint = "GCE_METADATA_HOST=set" if os.environ.get("GCE_METADATA_HOST") else "GCE_METADATA_HOST=unset"
        cred_hint = (
            "GOOGLE_APPLICATION_CREDENTIALS=external_account"
            if (
                os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
                and os.path.isfile(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", ""))
            )
            else "GOOGLE_APPLICATION_CREDENTIALS=unset_or_non_external"
        )
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
                async with session.get(metadata_url, headers={"Metadata-Flavor": "Google"}) as response:  # noqa: S310
                    if response.status != 200:
                        raise Exception(f"metadata status {response.status}")
            elapsed_ms = int((loop.time() - start) * 1000)
            self._log(f"Detected GCP metadata (elapsed={elapsed_ms}ms)")
            self._detected = True
            return
        except Exception as e:  # noqa: BLE001
            elapsed_ms = int((loop.time() - start) * 1000)
            msg = str(e) or type(e).__name__
            lower = msg.lower()
            if any(p in lower for p in ("name or service not known", "temporary failure", "not known")):
                category = "dns"
            elif any(p in lower for p in ("timed out", "timeout")):
                category = "timeout"
            elif any(p in lower for p in ("refused", "connection reset")):
                category = "connect"
            else:
                category = "other"
            diag = (
                "Not running on GCP: metadata probe failed; "
                f"elapsed_ms={elapsed_ms} category={category} timeout_s={per_attempt_timeout} "
                f"env=[{env_hint} {cred_hint}] exception_type={type(e).__name__} detail={msg}"
            )
            self._log(diag)
            raise Exception(diag)

        raise Exception(
            "Not running on GCP: no environment variable, metadata service, or default credentials detected"
        )

    async def fast_detect(self) -> None:
        """Fast detection: env/file only, no network."""
        # external_account credential file
        cred_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if cred_path and os.path.isfile(cred_path):
            try:  # noqa: BLE001
                with open(cred_path, "r", encoding="utf-8") as f:
                    content = f.read(4096)
                if '"type"' in content and '"external_account"' in content:
                    self._log("FastDetect: external_account credentials present")
                    self._detected = True
                    return
            except Exception as e:  # noqa: BLE001
                self._log(f"FastDetect: credential file read failed: {e}")

        if os.environ.get("GCE_METADATA_HOST"):
            # Do NOT verify network here; leave that to full detect
            self._log("FastDetect: GCE_METADATA_HOST present")
            self._detected = True
            return
        raise Exception("FastDetect: no GCP indicators")

    async def _verify_metadata_access(self) -> None:
        """Verify we can access identity-related metadata."""
        try:
            # Use asyncio.wait_for with explicit timeout (matches Go's pattern)
            async def check_identity_access() -> None:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as session:
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

        async with aiohttp.ClientSession() as session:
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
                    text_value = await response.text()
                    return str(text_value)
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
