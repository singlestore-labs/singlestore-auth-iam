"""JWT and assume-role parity tests mirroring Go s2iam_test.go."""

import base64
import json
import os
import subprocess
import time
import uuid
from contextlib import contextmanager
from typing import Iterator

import aiohttp
import pytest

import s2iam
from s2iam import CloudProviderType, JWTType
from s2iam.aws import DEFAULT_ROLE_SESSION_NAME, ROLE_SESSION_NAME_PARAM, _role_session_name_from_params

from .test_server_utils import GoTestServerManager
from .testhelp import require_cloud_role


def _go_dir() -> str:
    mgr = GoTestServerManager()
    return mgr.go_dir


@contextmanager
def _flagged_test_server(*extra_flags: str) -> Iterator[GoTestServerManager]:
    go_dir = _go_dir()
    build = subprocess.run(
        ["go", "build", "-o", "s2iam_test_server", "./cmd/s2iam_test_server"],
        cwd=go_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if build.returncode != 0:
        raise RuntimeError(f"failed to build test server: {build.stderr}")

    info_file = os.path.join(go_dir, f"s2iam_test_server_info_{os.getpid()}_{time.time_ns()}.json")
    cmd = [
        "./s2iam_test_server",
        "-port",
        "0",
        "-info-file",
        info_file,
        "-allowed-audiences",
        "https://authsvc.singlestore.com,https://test.example.com",
        "-timeout",
        "2m",
        *extra_flags,
    ]
    proc = subprocess.Popen(cmd, cwd=go_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 30
    port = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("test server exited early")
        if os.path.exists(info_file):
            try:
                with open(info_file) as f:
                    info = json.load(f)
                port = info["server_info"]["port"]
                if port:
                    break
            except (json.JSONDecodeError, KeyError, OSError):
                pass
        time.sleep(0.1)
    if not port:
        proc.terminate()
        raise RuntimeError("timed out waiting for flagged test server")

    mgr = GoTestServerManager(port=port, go_dir=go_dir)
    mgr.process = proc
    mgr.actual_port = port
    mgr.server_url = f"http://localhost:{port}"
    mgr.info_file = info_file
    try:
        yield mgr
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        try:
            os.remove(info_file)
        except OSError:
            pass


async def _fetch_last_server_request(base_url: str) -> dict | None:
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{base_url}/info/requests") as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            if not isinstance(data, list) or not data:
                return None
            return data[-1]


def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    assert len(parts) >= 2, "JWT structure invalid"
    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


@pytest.mark.asyncio
class TestCloudProviderNoRole:
    """Mirrors Go TestCloudProviderNoRole."""

    async def test_cloud_provider_no_role(self):
        no_role = os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
        if not no_role:
            pytest.skip("test requires S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")

        try:
            provider = await s2iam.detect_provider(timeout=10.0)
        except s2iam.CloudProviderNotFound:
            return
        except s2iam.ProviderIdentityUnavailable:
            return

        expected = {
            "aws": CloudProviderType.AWS,
            "gcp": CloudProviderType.GCP,
            "azure": CloudProviderType.AZURE,
        }.get(no_role)
        assert expected is not None, f"Unknown provider in S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE: {no_role}"
        assert provider.get_type() == expected

        with pytest.raises((s2iam.ProviderIdentityUnavailable, Exception)):
            await provider.get_identity_headers()


@pytest.mark.asyncio
class TestAssumeRoleInvalid:
    """Mirrors Go TestGetDatabaseJWT_AssumeRole_InvalidRole."""

    async def test_assume_role_invalid_role(self):
        provider = await require_cloud_role(timeout=10.0)
        ts = int(time.time())

        if provider.get_type() == CloudProviderType.AWS:
            invalid_role = f"arn:aws:iam::123456789012:role/NonExistentRole-{ts}"
        elif provider.get_type() == CloudProviderType.GCP:
            invalid_role = (
                f"projects/fake-project/serviceAccounts/nonexistent-{ts}@fake-project.iam.gserviceaccount.com"
            )
        elif provider.get_type() == CloudProviderType.AZURE:
            invalid_role = str(uuid.UUID(int=ts & ((1 << 128) - 1)))
        else:
            pytest.skip(f"unsupported provider: {provider.get_type()}")

        with _flagged_test_server() as server:
            with pytest.raises(Exception):
                await s2iam.get_jwt_database(
                    workspace_group_id="test-workspace",
                    server_url=f"{server.server_url}/auth/iam/database",
                    allow_http=True,
                    provider=provider,
                    assume_role_identifier=invalid_role,
                )


@pytest.mark.asyncio
class TestJwtErrorCases:
    """Mirrors Go JWT error-path tests against the Go test server."""

    async def _jwt_url(self, server: GoTestServerManager) -> str:
        return f"{server.server_url}/auth/iam/database"

    @pytest.mark.integration
    async def test_empty_jwt(self):
        provider = await require_cloud_role(timeout=10.0)
        with _flagged_test_server("-return-empty-jwt") as server:
            with pytest.raises(Exception, match="(?i)empty|no jwt"):
                await s2iam.get_jwt(
                    jwt_type=JWTType.DATABASE_ACCESS,
                    workspace_group_id="test-workspace",
                    server_url=await self._jwt_url(server),
                    allow_http=True,
                    provider=provider,
                )

    @pytest.mark.integration
    async def test_invalid_json(self):
        provider = await require_cloud_role(timeout=10.0)
        with _flagged_test_server("-return-invalid-json") as server:
            with pytest.raises(Exception, match="(?i)parse|json"):
                await s2iam.get_jwt(
                    jwt_type=JWTType.DATABASE_ACCESS,
                    workspace_group_id="test-workspace",
                    server_url=await self._jwt_url(server),
                    allow_http=True,
                    provider=provider,
                )

    @pytest.mark.integration
    async def test_server_error_500(self):
        provider = await require_cloud_role(timeout=10.0)
        with _flagged_test_server("-return-error", "-error-code", "500") as server:
            with pytest.raises(Exception, match="500"):
                await s2iam.get_jwt(
                    jwt_type=JWTType.DATABASE_ACCESS,
                    workspace_group_id="test-workspace",
                    server_url=await self._jwt_url(server),
                    allow_http=True,
                    provider=provider,
                )

    @pytest.mark.integration
    async def test_verification_failure_401(self):
        provider = await require_cloud_role(timeout=10.0)
        with _flagged_test_server("-fail-verification") as server:
            with pytest.raises(Exception, match="401"):
                await s2iam.get_jwt(
                    jwt_type=JWTType.DATABASE_ACCESS,
                    workspace_group_id="test-workspace",
                    server_url=await self._jwt_url(server),
                    allow_http=True,
                    provider=provider,
                )


class TestAwsRoleSessionName:
    def test_default_session_name(self):
        assert _role_session_name_from_params(None) == DEFAULT_ROLE_SESSION_NAME
        assert _role_session_name_from_params({}) == DEFAULT_ROLE_SESSION_NAME

    def test_custom_session_name(self):
        assert _role_session_name_from_params({ROLE_SESSION_NAME_PARAM: "my-app"}) == "my-app"


@pytest.mark.asyncio
async def test_assume_role_server_identity_matches_jwt_sub():
    role = os.environ.get("S2IAM_TEST_ASSUME_ROLE")
    if not role:
        pytest.skip("test requires S2IAM_TEST_ASSUME_ROLE")

    await require_cloud_role(timeout=10.0)
    with _flagged_test_server() as server:
        server_url = f"{server.server_url}/auth/iam/database"
        assumed_jwt = await s2iam.get_jwt_database(
            workspace_group_id="test-workspace",
            server_url=server_url,
            allow_http=True,
            assume_role_identifier=role,
        )
        claims = _decode_jwt_payload(assumed_jwt)
        last_req = await _fetch_last_server_request(server.server_url)
        assert last_req is not None
        server_identifier = last_req.get("identity", {}).get("identifier", "")
        assert server_identifier == claims.get("sub", "")


@pytest.mark.asyncio
async def test_no_provider_outside_cloud():
    if (
        os.environ.get("S2IAM_TEST_CLOUD_PROVIDER")
        or os.environ.get("S2IAM_TEST_ASSUME_ROLE")
        or os.environ.get("S2IAM_TEST_CLOUD_PROVIDER_NO_ROLE")
    ):
        pytest.skip("configured cloud test environment")

    with pytest.raises(s2iam.CloudProviderNotFound):
        await s2iam.detect_provider(timeout=1.0)
