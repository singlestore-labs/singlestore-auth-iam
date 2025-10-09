"""
Main API for the s2iam library.
"""

import asyncio
import os
import queue
import threading
import time
from typing import Any, Dict, List, NoReturn, Optional

from .aws import new_client as new_aws_client
from .azure import new_client as new_azure_client
from .gcp import new_client as new_gcp_client
from .models import (
    CloudProviderClient,
    CloudProviderNotFound,
    Logger,
)

DETECT_PROVIDER_DEFAULT_TIMEOUT: float = 5.0
"""Default timeout (seconds) for provider detection (mirrors Go implementation)."""


class DefaultLogger:
    """Default logger implementation."""

    def log(self, message: str) -> None:
        """Log a message to stdout."""
        print(f"[s2iam] {message}")


async def detect_provider(
    timeout: float = DETECT_PROVIDER_DEFAULT_TIMEOUT,
    logger: Optional[Logger] = None,
    clients: Optional[list[CloudProviderClient]] = None,
) -> CloudProviderClient:
    """
    Detect which cloud provider we're running on.

    Args:
        timeout: Detection timeout in seconds
        logger: Optional logger instance
        clients: Optional list of custom provider clients

    Returns:
        CloudProviderClient for the detected provider

    Raises:
        CloudProviderNotFound: If no provider can be detected
    """
    # Set up logger only if explicit debugging flag is set; production code must not branch
    # on test harness-only environment variables. Rich diagnostics are instead
    # surfaced via aggregated exception messages below.
    debugging = os.environ.get("S2IAM_DEBUGGING") == "true"
    debug_timing = os.environ.get("S2IAM_DEBUG_TIMING") == "true"
    if logger is None and debugging:
        logger = DefaultLogger()

    # Create default clients if none provided
    if clients is None:
        clients = [
            new_aws_client(logger),
            new_gcp_client(logger),
            new_azure_client(logger),
        ]

    # Phase 1: fast_detect sequentially (purely local; must not do network I/O).
    for c in clients:
        try:
            await c.fast_detect()
            if logger:
                logger.log(f"Fast detected provider: {c.get_type().value}")
            return c
        except Exception:
            # Not detected via fast path; move to next provider.
            continue

    # Phase 2: full detection using threads (mirrors Go goroutines + first-winner channel).
    # Invariants relied upon here: each client's detect() MUST raise on negative outcome; only a
    # positively detected client (internal flag set) returns normally. This prevents selecting a
    # provider that will later fail with ProviderNotDetected when building identity headers.
    result_queue: "queue.Queue[CloudProviderClient]" = queue.Queue()
    stop_event = threading.Event()
    all_errors: list[str] = []
    errors_lock = threading.Lock()
    # Structured per-provider status for enhanced error reporting.
    # Each element: {provider, status=success|error|timeout|skipped, elapsed_ms?, error?}
    provider_status: List[Dict[str, Any]] = []
    status_lock = threading.Lock()

    def record_status(entry: Dict[str, Any]) -> None:
        with status_lock:
            provider_status.append(entry)

    def test_provider_sync(client: CloudProviderClient) -> None:
        """Test a provider in a thread (like Go goroutine)."""
        if stop_event.is_set():
            record_status({"provider": client.get_type().value, "status": "skipped"})
            return
        thread_start = time.monotonic()
        if logger and (debugging or debug_timing):
            logger.log(f"DETECT_THREAD_START provider={client.get_type().value} outer_timeout_s={timeout}")
        try:
            # Run the async detect() in this thread's event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(client.detect())
                # Success - put result in queue if we're first
                if not stop_event.is_set():
                    result_queue.put(client)
                    stop_event.set()  # Signal other threads to stop
                elapsed_ms = int((time.monotonic() - thread_start) * 1000)
                record_status(
                    {
                        "provider": client.get_type().value,
                        "status": "success",
                        "elapsed_ms": elapsed_ms,
                    }
                )
                if logger and (debugging or debug_timing):
                    logger.log(f"DETECT_THREAD_SUCCESS provider={client.get_type().value} elapsed_ms={elapsed_ms}")
            finally:
                loop.close()
        except Exception as e:
            with errors_lock:
                all_errors.append(f"Provider {client.get_type().value} detection failed: {e}")
            elapsed_ms = int((time.monotonic() - thread_start) * 1000)
            record_status(
                {
                    "provider": client.get_type().value,
                    "status": "error",
                    "elapsed_ms": elapsed_ms,
                    "error": str(e)[:400],
                }
            )
            if logger and (debugging or debug_timing):
                logger.log(f"DETECT_THREAD_ERROR provider={client.get_type().value} elapsed_ms={elapsed_ms} error={e}")

    # Start threads for each provider (like Go goroutines)
    threads = []
    for client in clients:
        thread = threading.Thread(target=test_provider_sync, args=(client,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Wait for first result or timeout (like Go select)
    detection_start = time.monotonic()
    try:
        result: CloudProviderClient = result_queue.get(timeout=timeout)
        stop_event.set()  # Ensure all threads stop
        total_elapsed_ms = int((time.monotonic() - detection_start) * 1000)

        if logger:
            if debugging or debug_timing:
                logger.log(
                    (
                        "DETECT_COMPLETE status=success "
                        f"provider={result.get_type().value} "
                        f"total_elapsed_ms={total_elapsed_ms}"
                    )
                )
            else:
                logger.log(f"Detected provider: {result.get_type().value}")
        return result

    except queue.Empty:
        _raise_detection_timeout(
            timeout=timeout,
            detection_start=detection_start,
            clients=clients,
            threads=threads,
            provider_status=provider_status,
            status_lock=status_lock,
            all_errors=all_errors,
            logger=logger,
            debugging=debugging,
            debug_timing=debug_timing,
            stop_event=stop_event,
        )


def _raise_detection_timeout(
    *,
    timeout: float,
    detection_start: float,
    clients: list[CloudProviderClient],
    threads: list[threading.Thread],
    provider_status: list[dict[str, Any]],
    status_lock: threading.Lock,
    all_errors: list[str],
    logger: Optional[Logger],
    debugging: bool,
    debug_timing: bool,
    stop_event: threading.Event,
) -> NoReturn:
    """Compose and raise CloudProviderNotFound for a detection timeout.

    Isolated to keep the main detect_provider flow skimmable and ease future
    experiments (e.g., per-provider granular timeouts or retry policy integration).
    """
    stop_event.set()
    for thread in threads:
        thread.join(timeout=0.05)
    total_elapsed_ms = int((time.monotonic() - detection_start) * 1000)
    with status_lock:
        known = {p["provider"] for p in provider_status}
        for c in clients:
            name = c.get_type().value
            if name not in known:
                provider_status.append({"provider": name, "status": "timeout"})
    if logger and (debugging or debug_timing):
        joined_errors_dbg = " | ".join(all_errors)[:800]
        logger.log(
            (
                "DETECT_COMPLETE status=timeout "
                f"total_elapsed_ms={total_elapsed_ms} timeout_s={timeout} "
                f"errors='{joined_errors_dbg}'"
            )
        )
    summary_parts: list[str] = []
    for ps in provider_status:
        part = f"{ps['provider']}:{ps['status']}"
        if "elapsed_ms" in ps:
            part += f"@{ps['elapsed_ms']}ms"
        summary_parts.append(part)
    summary = ", ".join(summary_parts)
    joined_errors = " | ".join(all_errors)[:800] if all_errors else "<no-provider-errors>"
    meta = (
        f"timeout_s={timeout} total_elapsed_ms={total_elapsed_ms} providers={len(clients)} "
        f"error_count={len(all_errors)} provider_status=[{summary}]"
    )
    raise CloudProviderNotFound(f"Provider detection timed out: {meta} errors=[{joined_errors}]")
