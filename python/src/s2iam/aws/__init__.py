"""AWS cloud provider client implementation.

Single implementation aligned with the Go reference: fast env/IMDS detection,
STS fallback, optional role assumption, region derivation, and identity header
generation.
"""

import asyncio
import os
from typing import Any, Optional

from ..models import (
    CloudIdentity,
    CloudProviderClient,
    CloudProviderType,
    Logger,
    ProviderIdentityUnavailable,
    ProviderNotDetected,
)

ROLE_SESSION_NAME_PARAM = "roleSessionName"
# Stable default when AssumeRole is used without an explicit session name.
DEFAULT_ROLE_SESSION_NAME = "s2iam-session"

# Claim keys populated in CloudIdentity.additional_claims for AWS identities.
CLAIM_USER_ID = "UserId"
CLAIM_ASSUMED_ROLE_ARN = "AssumedRoleArn"
CLAIM_ROLE_SESSION_NAME = "RoleSessionName"


def _role_session_name_from_params(additional_params: Optional[dict[str, str]]) -> str:
    if additional_params:
        name = additional_params.get(ROLE_SESSION_NAME_PARAM)
        if name:
            return name
    return DEFAULT_ROLE_SESSION_NAME


def _parse_assumed_role_arn(arn: str) -> Optional[tuple[str, str]]:
    """Return (role_name, session_name) for an STS assumed-role ARN, else None.

    Format: arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION. Neither ROLE nor
    SESSION may contain '/'.
    """
    parts = arn.split(":")
    if len(parts) < 6 or parts[2] != "sts":
        return None
    segments = parts[5].split("/", 2)
    if len(segments) < 2 or segments[0] != "assumed-role" or not segments[1]:
        return None
    session_name = segments[2] if len(segments) == 3 else ""
    return segments[1], session_name


def _arn_resource_type(arn: str) -> str:
    parts = arn.split(":")
    if len(parts) >= 6:
        resource_parts = parts[5].split("/")
        if len(resource_parts) >= 2 and resource_parts[0]:
            return resource_parts[0]
    return ""


def canonical_identity(arn: str, account: str, user_id: str = "") -> tuple[str, str, dict[str, str]]:
    """Derive the single, stable principal identity from a GetCallerIdentity ARN.

    AWS STS assumed-role sessions collapse to their base IAM role ARN
    (arn:aws:iam::ACCOUNT:role/ROLE). The STS session name is caller-chosen and is
    not a trustworthy authorization boundary; the IAM role is gated by its trust
    policy, and role names are unique within an account. The raw assumed-role ARN
    and session name are preserved in the returned claims for audit. All other
    identities (IAM users, etc.) are returned unchanged.

    Note: the STS assumed-role ARN omits the IAM path, so for a pathed role the
    derived identity is the path-less canonical form.
    """
    claims: dict[str, str] = {}
    if user_id:
        claims[CLAIM_USER_ID] = user_id

    identifier = arn
    resource_type = _arn_resource_type(arn)

    parsed = _parse_assumed_role_arn(arn)
    if parsed is not None:
        role_name, session_name = parsed
        identifier = f"arn:aws:iam::{account}:role/{role_name}"
        resource_type = "role"
        claims[CLAIM_ASSUMED_ROLE_ARN] = arn
        if session_name:
            claims[CLAIM_ROLE_SESSION_NAME] = session_name

    return identifier, resource_type, claims


class AWSClient(CloudProviderClient):
    _logger: Optional[Logger]
    _detected: bool
    _region: Optional[str]
    _identity: Optional[CloudIdentity]
    _role_arn: Optional[str]
    _sts_client: Optional[Any]
    _session: Optional[Any]

    def __init__(self, logger: Optional[Logger] = None):
        self._logger = logger
        self._detected = False
        self._region = None
        self._identity = None
        self._role_arn = None
        self._sts_client = None
        self._session = None

    def _log(self, message: str) -> None:
        if self._logger:
            self._logger.log(f"AWS: {message}")

    async def _check_metadata_service(self) -> bool:
        """Best-effort IMDSv2 then IMDSv1 probe (<= ~3s worst case)."""
        try:  # noqa: BLE001
            import aiohttp

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
                async with session.put(
                    "http://169.254.169.254/latest/api/token",
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                ) as token_resp:
                    if token_resp.status == 200:
                        token = await token_resp.text()
                        async with session.get(
                            "http://169.254.169.254/latest/meta-data/instance-id",
                            headers={"X-aws-ec2-metadata-token": token},
                        ) as resp:
                            if resp.status == 200:
                                return True

                async with session.get(
                    "http://169.254.169.254/latest/meta-data/instance-id",
                    timeout=aiohttp.ClientTimeout(total=2),
                ) as resp:
                    return resp.status == 200
        except Exception as e:  # noqa: BLE001
            self._log(f"Metadata service check failed: {e}")
            return False

    async def detect(self) -> None:
        # Full (network-inclusive) detection. Raise on failure so orchestrator never
        # selects an undetected client (prevents later ProviderNotDetected errors).
        self._log("Starting AWS detection (full phase)")
        if self._detected:
            return

        if await self._check_metadata_service():
            self._detected = True
            self._log("Detected via metadata service")
            return

        try:
            import boto3  # optional dependency in some usage contexts
        except ImportError as e:  # noqa: BLE001
            self._log(f"boto3 import failed: {e}")
        else:
            try:  # noqa: BLE001
                sts_client = boto3.client("sts")
                identity = sts_client.get_caller_identity()
                if identity.get("Account"):
                    self._detected = True
                    self._log("Detected via STS")
                    return
            except Exception as e:  # noqa: BLE001
                self._log(f"STS detection failed: {e}")

        self._log("AWS full detection did not succeed; raising")
        raise Exception("AWS provider not detected")

    async def fast_detect(self) -> None:
        """Fast detection: env only, no network calls."""
        # IRSA / web identity short-circuit: ONLY honor explicit env vars.
        if os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE") or os.environ.get("AWS_ROLE_ARN"):
            self._detected = True
            self._log("FastDetect: IRSA environment variables present")
            return

        for var in ("AWS_EXECUTION_ENV", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_LAMBDA_FUNCTION_NAME"):
            if os.environ.get(var):
                self._detected = True
                self._log(f"FastDetect: detected via env var {var}")
                return
        raise Exception("FastDetect: no AWS indicators")

    async def _ensure_region(self) -> None:
        if self._region:
            return

        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if not region:
            try:  # noqa: BLE001
                import aiohttp

                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
                    async with session.put(
                        "http://169.254.169.254/latest/api/token",
                        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                    ) as token_resp:
                        if token_resp.status == 200:
                            token = await token_resp.text()
                            async with session.get(
                                "http://169.254.169.254/latest/meta-data/placement/region",
                                headers={"X-aws-ec2-metadata-token": token},
                            ) as region_resp:
                                if region_resp.status == 200:
                                    region = await region_resp.text()
                                    self._log(f"Region from metadata: {region}")
            except Exception as e:  # noqa: BLE001
                self._log(f"Region metadata lookup failed: {e}")

        if not region:
            region = "us-east-1"
            self._log("Defaulting region to us-east-1")
        self._region = region

    def get_type(self) -> CloudProviderType:
        return CloudProviderType.AWS

    def assume_role(self, role_identifier: str) -> "AWSClient":
        clone = AWSClient(self._logger)
        clone._detected = self._detected
        clone._region = self._region
        clone._role_arn = role_identifier
        clone._sts_client = self._sts_client
        return clone

    async def get_identity_headers(
        self, additional_params: Optional[dict[str, str]] = None
    ) -> tuple[dict[str, str], CloudIdentity]:  # noqa: D401,E501
        if not self._detected:
            raise ProviderNotDetected("AWS provider not detected, call detect() first")

        if not self._sts_client:
            import boto3

            await self._ensure_region()
            self._session = boto3.Session()
            self._sts_client = self._session.client("sts", region_name=self._region)
            self._log("Initialized STS client")

        if self._sts_client is None or self._session is None:
            # Can happen when clone created via assume_role (sts_client copied but session not)
            import boto3

            if self._session is None:
                self._session = boto3.Session()
            if self._sts_client is None:
                self._sts_client = self._session.client("sts", region_name=self._region)
            self._log("Recovered missing STS session/client state")

        # Narrow optionals after explicit check
        sts_client = self._sts_client
        session_obj = self._session

        loop = asyncio.get_event_loop()

        try:  # noqa: BLE001
            if self._role_arn:
                session_name = _role_session_name_from_params(additional_params)
                self._log(f"Assuming role {self._role_arn} with session name {session_name}")
                assume_resp = await loop.run_in_executor(
                    None,
                    lambda: sts_client.assume_role(
                        RoleArn=self._role_arn,
                        RoleSessionName=session_name,
                    ),
                )
                creds = assume_resp["Credentials"]
                import boto3

                assumed_session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=self._region,
                )
                assumed_sts = assumed_session.client("sts")
                identity_resp = await loop.run_in_executor(None, assumed_sts.get_caller_identity)
                headers = {
                    "X-AWS-Access-Key-ID": creds["AccessKeyId"],
                    "X-AWS-Secret-Access-Key": creds["SecretAccessKey"],
                    "X-AWS-Session-Token": creds["SessionToken"],
                }
            else:
                identity_resp = await loop.run_in_executor(None, sts_client.get_caller_identity)
                role_assumed = (
                    ":assumed-role/" in identity_resp["Arn"] or os.environ.get("AWS_SESSION_TOKEN") is not None
                )
                if role_assumed:
                    creds = session_obj.get_credentials()
                    headers = {
                        "X-AWS-Access-Key-ID": creds.access_key,
                        "X-AWS-Secret-Access-Key": creds.secret_key,
                        "X-Cloud-Provider": "aws",
                    }
                    if creds.token:
                        headers["X-AWS-Session-Token"] = creds.token
                    if os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE") or os.environ.get("AWS_ROLE_ARN"):
                        self._log("Using IRSA web identity session credentials")
                else:
                    self._log("Getting session token for static credentials")
                    session_resp = await loop.run_in_executor(None, sts_client.get_session_token)
                    sc = session_resp["Credentials"]
                    headers = {
                        "X-AWS-Access-Key-ID": sc["AccessKeyId"],
                        "X-AWS-Secret-Access-Key": sc["SecretAccessKey"],
                        "X-AWS-Session-Token": sc["SessionToken"],
                        "X-Cloud-Provider": "aws",
                    }

            arn = identity_resp["Arn"]
            parts = arn.split(":")
            # Region comes from the raw ARN (empty for assumed-role STS ARNs).
            region_from_arn = parts[3] if len(parts) > 3 else ""

            # If region unset locally (IRSA path without env/metadata), adopt ARN region
            if not self._region and region_from_arn:
                self._region = region_from_arn
                self._log(f"Derived region from ARN: {self._region}")

            # Collapse assumed-role sessions to the base IAM role ARN (the single,
            # stable mapping shared with the Go verifier / authority).
            identifier, resource_type, claims = canonical_identity(
                arn, identity_resp["Account"], identity_resp.get("UserId", "")
            )

            identity = CloudIdentity(
                provider=CloudProviderType.AWS,
                identifier=identifier,
                account_id=identity_resp["Account"],
                region=region_from_arn,
                resource_type=resource_type,
                additional_claims=claims,
            )
            self._log(f"Generated headers for identity: {identity.identifier}")
            return headers, identity
        except Exception as e:  # noqa: BLE001
            self._log(f"Failed to build identity headers: {e}")
            raise ProviderIdentityUnavailable(f"Failed to get AWS identity: {e}")


def new_client(logger: Optional[Logger] = None) -> CloudProviderClient:
    return AWSClient(logger)
