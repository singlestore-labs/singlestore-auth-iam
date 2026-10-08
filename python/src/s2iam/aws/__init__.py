"""AWS cloud provider client implementation.

Single implementation aligned with the Go reference: fast env/IMDS detection,
STS fallback, optional role assumption, region derivation, and identity header
generation.
"""

import asyncio
import os
from typing import Any, Optional

from botocore.utils import ArnParser

try:  # botocore moved this between versions
    from botocore.exceptions import InvalidArnException
except ImportError:  # pragma: no cover
    from botocore.utils import InvalidArnException

from ..identity_format import (
    FORMAT_AWS_ARN,
    FORMAT_AWS_IAM_ROLE_ARN,
    FORMAT_AWS_ROLE_ID,
    IdentityCandidate,
)
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


_ARN_PARSER = ArnParser()


def _parse_arn(arn: str) -> Optional[dict[str, str]]:
    """Parse an ARN into its components with botocore, or None if malformed.

    Returns a dict with keys partition, service, region, account, resource.
    Uses botocore (already a dependency via boto3) rather than hand-rolled
    ':'-splitting; the resource keeps any internal delimiters verbatim.
    """
    try:
        parsed: dict[str, str] = _ARN_PARSER.parse_arn(arn)
    except InvalidArnException:
        return None
    return parsed


def _parse_assumed_role_arn(arn: str) -> Optional[tuple[str, str, str]]:
    """Return (partition, role_name, session_name) for an STS assumed-role ARN, else None.

    Format: arn:PARTITION:sts::ACCOUNT:assumed-role/ROLE/SESSION. The resource
    sub-structure is not modeled by the parser, so it is split here; neither ROLE
    nor SESSION may contain '/'.
    """
    parsed = _parse_arn(arn)
    if parsed is None or parsed["service"] != "sts":
        return None
    segments = parsed["resource"].split("/", 2)
    if len(segments) < 2 or segments[0] != "assumed-role" or not segments[1]:
        return None
    session_name = segments[2] if len(segments) == 3 else ""
    return parsed["partition"], segments[1], session_name


def _arn_resource_type(arn: str) -> str:
    parsed = _parse_arn(arn)
    if parsed is None:
        return ""
    resource = parsed["resource"]
    resource_type = resource.split("/", 1)[0] if "/" in resource else ""
    return resource_type


def _role_id_from_user_id(user_id: str) -> str:
    """Return the immutable RoleId portion of an STS UserId.

    UserId is "AROA...:session" for assumed roles; the RoleId is the segment
    before the ':'.
    """
    if ":" in user_id:
        return user_id.split(":", 1)[0]
    return ""


def _aws_candidates(arn: str, account: str, user_id: str = "") -> list[IdentityCandidate]:
    """Return the identity formats valid for the attested GetCallerIdentity result.

    Natural order with the always-valid floor (the raw caller ARN) first:

      - aws-arn (floor, always): the raw caller ARN.
      - aws-iam-role-arn (assumed-role only): the base IAM role ARN
        (arn:aws:iam::ACCOUNT:role/ROLE). The STS session name is caller-chosen and
        is not a trustworthy authorization boundary; the IAM role is gated by its
        trust policy, and role names are unique within an account.
      - aws-role-id (assumed-role only): the immutable RoleId (AROA...), the prefix
        of the STS UserId.

    Note: the STS assumed-role ARN omits the IAM path, so the derived base role ARN
    is the path-less canonical form. This must stay identical between the client and
    the Go verifier so the client-computed identity matches the issued JWT sub.
    """
    candidates = [IdentityCandidate(FORMAT_AWS_ARN, arn)]

    parsed = _parse_assumed_role_arn(arn)
    if parsed is not None:
        partition, role_name, _ = parsed
        # Preserve the source partition (aws, aws-us-gov, aws-cn); the STS
        # assumed-role ARN omits the IAM path, so this is the path-less canonical
        # form arn:PARTITION:iam::ACCOUNT:role/ROLE.
        base_role_arn = f"arn:{partition}:iam::{account}:role/{role_name}"
        candidates.append(IdentityCandidate(FORMAT_AWS_IAM_ROLE_ARN, base_role_arn))
        role_id = _role_id_from_user_id(user_id)
        if role_id:
            candidates.append(IdentityCandidate(FORMAT_AWS_ROLE_ID, role_id))

    return candidates


def _aws_identity_claims(arn: str, user_id: str = "") -> dict[str, str]:
    """Build AdditionalClaims for an AWS identity.

    The raw STS assumed-role ARN, the role session name, and the STS UserId (whose
    prefix is the role's immutable RoleId) are preserved for registration-preview
    and audit, independent of the negotiated identity format.
    """
    claims: dict[str, str] = {}
    if user_id:
        claims[CLAIM_USER_ID] = user_id
    parsed = _parse_assumed_role_arn(arn)
    if parsed is not None:
        _, _, session_name = parsed
        claims[CLAIM_ASSUMED_ROLE_ARN] = arn
        if session_name:
            claims[CLAIM_ROLE_SESSION_NAME] = session_name
    return claims


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
            # Region comes from the raw ARN (empty for assumed-role STS ARNs).
            parsed_arn = _parse_arn(arn)
            region_from_arn = parsed_arn["region"] if parsed_arn else ""

            # If region unset locally (IRSA path without env/metadata), adopt ARN region
            if not self._region and region_from_arn:
                self._region = region_from_arn
                self._log(f"Derived region from ARN: {self._region}")

            # Build the valid identity-format candidates and default the identifier
            # to the always-valid floor (the raw caller ARN, format aws-arn), which
            # is byte-identical to the historical behavior. The negotiated format
            # (chosen by the verifier from the preference header) may select an
            # alternate such as the base IAM role ARN; the candidate set lets the
            # client re-derive the chosen value.
            account = identity_resp["Account"]
            user_id = identity_resp.get("UserId", "")
            candidates = _aws_candidates(arn, account, user_id)

            identity = CloudIdentity(
                provider=CloudProviderType.AWS,
                identifier=candidates[0].value,
                account_id=account,
                region=region_from_arn,
                resource_type=_arn_resource_type(arn),
                additional_claims=_aws_identity_claims(arn, user_id),
                identity_format=candidates[0].format,
                candidates=[(c.format, c.value) for c in candidates],
            )
            self._log(f"Generated headers for identity: {identity.identifier}")
            return headers, identity
        except Exception as e:  # noqa: BLE001
            self._log(f"Failed to build identity headers: {e}")
            raise ProviderIdentityUnavailable(f"Failed to get AWS identity: {e}")


def new_client(logger: Optional[Logger] = None) -> CloudProviderClient:
    return AWSClient(logger)
