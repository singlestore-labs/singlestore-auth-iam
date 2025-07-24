"""
AWS cloud provider client implementation.
"""

import asyncio
import json
import os
from typing import Dict, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from ..models import (
    CloudIdentity,
    CloudProviderClient,
    CloudProviderType,
    Logger,
    ProviderDetectedNoIdentityError,
    ProviderNotDetectedError,
)


class AWSClient(CloudProviderClient):
    """AWS implementation of CloudProviderClient."""
    
    def __init__(self, logger: Optional[Logger] = None):
        self._logger = logger
        self._detected = False
        self._region: Optional[str] = None
        self._identity: Optional[CloudIdentity] = None
        self._role_arn: Optional[str] = None
        self._sts_client: Optional[object] = None
    
    def _log(self, message: str) -> None:
        """Log a message if logger is available."""
        if self._logger:
            self._logger.log(f"AWS: {message}")
    
    async def _check_metadata_service(self) -> bool:
        """Check AWS metadata service using IMDSv2.
        
        AWS Instance Metadata Service v2 (IMDSv2) is the preferred method:
        1. Get a session token first via PUT request
        2. Use token in subsequent metadata requests
        3. Fall back to IMDSv1 (no token) for compatibility
        
        This matches the detection strategy used in the Go implementation.
        """
        try:
            import aiohttp
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
                # Try to get IMDSv2 token first
                async with session.put(
                    "http://169.254.169.254/latest/api/token",
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
                ) as token_resp:
                    if token_resp.status == 200:
                        token = await token_resp.text()
                        
                        # Try to get instance metadata with token
                        async with session.get(
                            "http://169.254.169.254/latest/meta-data/instance-id",
                            headers={"X-aws-ec2-metadata-token": token}
                        ) as resp:
                            return resp.status == 200
                    
                    # Fallback: try without token (IMDSv1)
                    async with session.get(
                        "http://169.254.169.254/latest/meta-data/instance-id",
                        timeout=aiohttp.ClientTimeout(total=2)
                    ) as resp:
                        return resp.status == 200
                        
        except Exception as e:
            self._log(f"Metadata service check failed: {e}")
            return False
    
    async def detect(self) -> None:
        """Detect if running on AWS (matches Go implementation)."""
        self._log("Starting AWS detection")

        # Fast path: Check all relevant AWS environment variables
        env_vars = [
            "AWS_EXECUTION_ENV",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
            "AWS_LAMBDA_FUNCTION_NAME",
            "ECS_CONTAINER_METADATA_URI",
            "ECS_CONTAINER_METADATA_URI_V4",
        ]
        for var in env_vars:
            if os.environ.get(var):
                self._log(f"Found AWS environment variable: {var}")
                self._detected = True
                return

        # Metadata service: Try IMDSv2/IMDSv1
        if await self._check_metadata_service():
            self._log("AWS metadata service detected")
            # Ensure region is set
            await self._ensure_region()
            # Initialize STS client with detected region
            try:
                session = boto3.Session()
                self._sts_client = session.client("sts", region_name=self._region)
                self._log("STS client initialized after metadata service detection")
            except Exception as e:
                self._log(f"Warning: Could not initialize STS client after metadata detection: {e}")
            self._detected = True
            return

        # STS fallback: Try boto3 STS client
        try:
            self._sts_client = boto3.client("sts")
            identity = self._sts_client.get_caller_identity()
            if identity and identity.get("Account"):
                self._log("AWS STS client detected")
                self._detected = True
                return
        except Exception as e:
            self._log(f"AWS STS client detection failed: {e}")

        raise Exception("Not running on AWS: no environment variable, metadata service, or STS client detected")
        # Try AWS metadata service (IMDSv2)
        if await self._check_metadata_service():
            self._log("AWS detection successful via metadata service")
            self._detected = True
            # Still need to set up STS client for getting identity headers
            try:
                await self._ensure_region()
                session = boto3.Session()
                self._sts_client = session.client("sts", region_name=self._region)
                self._log("STS client initialized after metadata service detection")
            except Exception as e:
                self._log(f"Warning: Could not initialize STS client after metadata detection: {e}")
            return
        
        # Fallback: Try STS client as last resort
        try:
            # Try to determine region first
            await self._ensure_region()
            
            # Create STS client
            session = boto3.Session()
            self._sts_client = session.client("sts", region_name=self._region)
            
            # Test by getting caller identity
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, self._sts_client.get_caller_identity
            )
            
            self._detected = True
            self._log(f"AWS detection successful via STS, caller identity: {response.get('Arn', 'unknown')}")
            
        except (ClientError, BotoCoreError, NoCredentialsError) as e:
            self._log(f"AWS detection failed: {e}")
            raise Exception(f"Not running on AWS or no valid credentials: {e}")
    
    async def _ensure_region(self) -> None:
        """Determine and set the AWS region."""
        if self._region:
            return
        
        self._log("Determining AWS region")
        
        # Try environment variables first
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        
        if not region:
            # Try EC2 metadata service
            try:
                import aiohttp
                
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
                    # Get token first
                    async with session.put(
                        "http://169.254.169.254/latest/api/token",
                        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
                    ) as token_resp:
                        if token_resp.status == 200:
                            token = await token_resp.text()
                            
                            # Get region with token
                            async with session.get(
                                "http://169.254.169.254/latest/meta-data/placement/region",
                                headers={"X-aws-ec2-metadata-token": token}
                            ) as region_resp:
                                if region_resp.status == 200:
                                    region = await region_resp.text()
                                    self._log(f"Got region from metadata: {region}")
            except Exception as e:
                self._log(f"Failed to get region from metadata: {e}")
        
        # Fall back to default region
        if not region:
            region = "us-east-1"
            self._log(f"Using default region: {region}")
        
        self._region = region
    
    def get_type(self) -> CloudProviderType:
        """Return AWS provider type."""
        return CloudProviderType.AWS
    
    def assume_role(self, role_identifier: str) -> "AWSClient":
        """Create a new client with assumed role."""
        new_client = AWSClient(self._logger)
        new_client._detected = self._detected
        new_client._region = self._region
        new_client._role_arn = role_identifier
        new_client._sts_client = self._sts_client
        return new_client
    
    async def get_identity_headers(
        self, 
        additional_params: Optional[Dict[str, str]] = None
    ) -> tuple[Dict[str, str], CloudIdentity]:
        """Get AWS identity headers."""
        if not self._detected:
            raise ProviderNotDetectedError("AWS provider not detected, call detect() first")
        
        if not self._sts_client:
            raise ProviderDetectedNoIdentityError("No STS client available")
        
        try:
            loop = asyncio.get_event_loop()
            
            # If assuming a role, do that first
            if self._role_arn:
                self._log(f"Assuming role: {self._role_arn}")
                assume_response = await loop.run_in_executor(
                    None,
                    lambda: self._sts_client.assume_role(
                        RoleArn=self._role_arn,
                        RoleSessionName="s2iam-session"
                    )
                )
                
                credentials = assume_response["Credentials"]
                
                # Create new STS client with assumed role credentials
                assumed_session = boto3.Session(
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                    region_name=self._region
                )
                assumed_sts = assumed_session.client("sts")
                
                # Get identity with assumed role
                identity_response = await loop.run_in_executor(
                    None, assumed_sts.get_caller_identity
                )
            else:
                # Get current identity
                identity_response = await loop.run_in_executor(
                    None, self._sts_client.get_caller_identity
                )
            
            # Create identity object
            identity = CloudIdentity(
                provider=CloudProviderType.AWS,
                identifier=identity_response["Arn"],
                account_id=identity_response["Account"],
                region=self._region or "",
                resource_type="aws-identity"
            )
            
            # Create headers - for AWS we'll use the identity info directly
            # In a real implementation, this would get a token from AWS STS
            headers = {
                "X-Cloud-Provider": "aws",
                "X-AWS-Account-ID": identity_response["Account"],
                "X-AWS-ARN": identity_response["Arn"],
                "X-AWS-User-ID": identity_response["UserId"],
                "X-AWS-Region": self._region or "",
            }
            
            self._log(f"Generated headers for identity: {identity.identifier}")
            return headers, identity
            
        except Exception as e:
            self._log(f"Failed to get identity headers: {e}")
            raise ProviderDetectedNoIdentityError(f"Failed to get AWS identity: {e}")


def new_client(logger: Optional[Logger] = None) -> CloudProviderClient:
    """Create a new AWS client."""
    return AWSClient(logger)
