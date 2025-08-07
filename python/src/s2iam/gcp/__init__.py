"""
Google Cloud Platform provider client implementation.
"""

import asyncio
import json
import os
from typing import Dict, Optional

import aiohttp
from google.auth import default
from google.auth.transport.requests import Request

from ..models import (
    CloudIdentity,
    CloudProviderClient,
    CloudProviderType,
    Logger,
    ProviderDetectedNoIdentityError,
    ProviderNotDetectedError,
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
        """Detect if running on GCP."""
        self._log("Starting GCP detection")
        
        # Check GCP environment variable first
        if os.environ.get("GCE_METADATA_HOST"):
            self._log("Found GCE_METADATA_HOST environment variable")
            await self._verify_metadata_access()
            self._detected = True
            return
        
        # Try to access metadata service
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
                async with session.get(
                    "http://metadata.google.internal/computeMetadata/v1/instance/id",
                    headers={"Metadata-Flavor": "Google"}
                ) as response:
                    if response.status == 200:
                        self._log("Successfully accessed GCP metadata service")
                        self._detected = True
                        return
                    else:
                        self._log(f"Metadata service returned status {response.status}")
        except Exception as e:
            self._log(f"Failed to access GCP metadata service: {e}")
        
        # Try Google Auth default credentials as fallback
        try:
            credentials, project = default()
            if credentials and project:
                self._log("Found Google default credentials")
                self._detected = True
                return
        except Exception as e:
            self._log(f"No Google default credentials: {e}")
        
        raise Exception("Not running on GCP: no metadata service or default credentials")
    
    async def _verify_metadata_access(self) -> None:
        """Verify we can access identity-related metadata."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as session:
                async with session.get(
                    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/",
                    headers={"Metadata-Flavor": "Google"}
                ) as response:
                    if response.status != 200:
                        raise ProviderDetectedNoIdentityError(
                            "GCP metadata available but no identity access"
                        )
        except aiohttp.ClientError as e:
            raise ProviderDetectedNoIdentityError(
                f"Cannot access GCP identity metadata: {e}"
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
        self, 
        additional_params: Optional[Dict[str, str]] = None
    ) -> tuple[Dict[str, str], CloudIdentity]:
        """Get GCP identity headers."""
        if not self._detected:
            raise ProviderNotDetectedError("GCP provider not detected, call detect() first")
        
        audience = additional_params.get("audience", "https://auth.singlestore.com") if additional_params else "https://auth.singlestore.com"
        
        try:
            if self._service_account_email:
                # Get token through impersonation
                token = await self._get_impersonated_token(audience)
                project_info = await self._get_project_info()
                
                identity = CloudIdentity(
                    provider=CloudProviderType.GCP,
                    identifier=f"{project_info.get('projectNumber', '')}/{self._service_account_email}",
                    account_id=project_info.get("projectId", ""),
                    region=await self._get_zone(),
                    resource_type="gcp-service-account"
                )
            else:
                # Get default identity token
                token = await self._get_identity_token(audience)
                project_info = await self._get_project_info()
                service_account = await self._get_service_account()
                
                identity = CloudIdentity(
                    provider=CloudProviderType.GCP,
                    identifier=f"{project_info.get('projectNumber', '')}/{service_account}",
                    account_id=project_info.get("projectId", ""),
                    region=await self._get_zone(),
                    resource_type="gcp-compute-instance"
                )
            
            headers = {
                "X-Cloud-Provider": "gcp",
                "Authorization": f"Bearer {token}",
                "X-GCP-Project-ID": identity.account_id,
                "X-GCP-Project-Number": identity.identifier.split("/")[0] if "/" in identity.identifier else "",
                "X-GCP-Zone": identity.region,
            }
            
            self._log(f"Generated headers for identity: {identity.identifier}")
            return headers, identity
            
        except Exception as e:
            self._log(f"Failed to get identity headers: {e}")
            raise ProviderDetectedNoIdentityError(f"Failed to get GCP identity: {e}")
    
    async def _get_identity_token(self, audience: str) -> str:
        """Get identity token from metadata service."""
        url = f"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={audience}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers={"Metadata-Flavor": "Google"}
            ) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    raise Exception(f"Failed to get identity token: {response.status}")
    
    async def _get_impersonated_token(self, audience: str) -> str:
        """Get token through service account impersonation."""
        # First get our own token for authentication
        self_token = await self._get_identity_token("https://iamcredentials.googleapis.com/")
        
        # Request impersonated token
        url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{self._service_account_email}:generateIdToken"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers={
                    "Authorization": f"Bearer {self_token}",
                    "Content-Type": "application/json"
                },
                json={"audience": audience}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data["token"]
                else:
                    text = await response.text()
                    raise Exception(f"Impersonation failed with status {response.status}: {text}")
    
    async def _get_project_info(self) -> Dict[str, str]:
        """Get project information from metadata."""
        info = {}
        
        async with aiohttp.ClientSession() as session:
            # Get project ID
            try:
                async with session.get(
                    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                    headers={"Metadata-Flavor": "Google"}
                ) as response:
                    if response.status == 200:
                        info["projectId"] = await response.text()
            except Exception as e:
                self._log(f"Failed to get project ID: {e}")
            
            # Get project number
            try:
                async with session.get(
                    "http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id",
                    headers={"Metadata-Flavor": "Google"}
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
                headers={"Metadata-Flavor": "Google"}
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
                    headers={"Metadata-Flavor": "Google"}
                ) as response:
                    if response.status == 200:
                        zone_path = await response.text()
                        # Extract zone from path like "projects/123/zones/us-central1-a"
                        return zone_path.split("/")[-1] if "/" in zone_path else zone_path
        except Exception as e:
            self._log(f"Failed to get zone: {e}")
        
        return ""


def new_client(logger: Optional[Logger] = None) -> CloudProviderClient:
    """Create a new GCP client."""
    return GCPClient(logger)
