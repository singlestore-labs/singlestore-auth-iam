"""
Main API for the s2iam library.
"""

import asyncio
import os
import queue
import threading
import time
from typing import Optional

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
    # Set up logger if debugging is enabled
    debugging = os.environ.get("S2IAM_DEBUGGING") == "true"
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

    def test_provider_sync(client: CloudProviderClient) -> None:
        """Test a provider in a thread (like Go goroutine)."""
        if stop_event.is_set():
            return
        thread_start = time.monotonic()
        if logger and debugging:
            logger.log(f"DETECT_THREAD_START provider={client.get_type().value} " f"timeout_s={timeout}")
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
                if logger and debugging:
                    elapsed_ms = int((time.monotonic() - thread_start) * 1000)
                    logger.log(f"DETECT_THREAD_SUCCESS provider={client.get_type().value} " f"elapsed_ms={elapsed_ms}")
            finally:
                loop.close()
        except Exception as e:
            with errors_lock:
                all_errors.append(f"Provider {client.get_type().value} detection failed: {e}")
            if logger:
                elapsed_ms = int((time.monotonic() - thread_start) * 1000)
                logger.log(
                    f"DETECT_THREAD_ERROR provider={client.get_type().value} " f"elapsed_ms={elapsed_ms} error={e}"
                )

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
            if debugging:
                logger.log(
                    f"DETECT_COMPLETE status=success provider={result.get_type().value} "
                    f"total_elapsed_ms={total_elapsed_ms}"
                )
            else:
                logger.log(f"Detected provider: {result.get_type().value}")
        return result

    except queue.Empty:
        # Timeout occurred; signal threads to stop and join briefly.
        stop_event.set()
        for thread in threads:
            thread.join(timeout=0.05)
        total_elapsed_ms = int((time.monotonic() - detection_start) * 1000)
        if logger and debugging:
            # Collate errors into single line (avoid multi-line spam); length guard.
            joined_errors = " | ".join(all_errors)[:800]
            logger.log(
                f"DETECT_COMPLETE status=timeout total_elapsed_ms={total_elapsed_ms} "
                f"timeout_s={timeout} errors='{joined_errors}'"
            )
        raise CloudProviderNotFound(f"Provider detection timed out after {timeout}s")
