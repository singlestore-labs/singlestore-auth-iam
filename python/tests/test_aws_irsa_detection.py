import pytest

from s2iam.aws import new_client


class DummyLogger:
    def __init__(self):
        self.messages = []

    def log(self, msg: str) -> None:  # pragma: no cover - helper
        self.messages.append(msg)


@pytest.mark.asyncio
async def test_irsa_short_circuit_detection(monkeypatch):
    # Ensure other detection paths are absent
    for var in [
        "AWS_EXECUTION_ENV",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_LAMBDA_FUNCTION_NAME",
    ]:
        monkeypatch.delenv(var, raising=False)

    # Provide IRSA env var using a temp token file instead of cluster path
    import pathlib
    import tempfile

    tmp_dir = tempfile.TemporaryDirectory()
    token_path = pathlib.Path(tmp_dir.name) / "token"
    token_path.write_text("dummy")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(token_path))
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/MyServiceAccountRole")

    logger = DummyLogger()
    client = new_client(logger)

    # Fast detection should succeed immediately without invoking full detection network paths
    await client.fast_detect()
    assert any("IRSA environment" in m for m in logger.messages), logger.messages


@pytest.mark.asyncio
async def test_irsa_negative_without_vars(monkeypatch):
    monkeypatch.delenv("AWS_WEB_IDENTITY_TOKEN_FILE", raising=False)
    monkeypatch.delenv("AWS_ROLE_ARN", raising=False)
    # Remove env shortcuts
    for var in [
        "AWS_EXECUTION_ENV",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_LAMBDA_FUNCTION_NAME",
    ]:
        monkeypatch.delenv(var, raising=False)

    client = new_client()
    # Expect fast detection to fail immediately (no env indicators)
    with pytest.raises(Exception):  # broad: fast_detect raises generic Exception when no indicators
        await client.fast_detect()
