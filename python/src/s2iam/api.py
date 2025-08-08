"""
Main API for the s2iam library.
"""

import asyncio
import os
import threading
import queue
from typing import Optional

from .aws import new_client as new_aws_client
from .azure import new_client as new_azure_client
from .gcp import new_client as new_gcp_client
from .models import (
    CloudProviderClient,
    CloudProviderNotFound,
    Logger,
)


class DefaultLogger:
    """Default logger implementation."""

    def log(self, message: str) -> None:
        """Log a message to stdout."""
        print(f"[s2iam] {message}")


async def detect_provider(
    timeout: float = 5.0,
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
    if logger is None and os.environ.get("S2IAM_DEBUGGING") == "true":
        logger = DefaultLogger()

    # Create default clients if none provided
    if clients is None:
        clients = [
            new_aws_client(logger),
            new_gcp_client(logger),
            new_azure_client(logger),
        ]

    # Use threading approach that mirrors Go goroutines + channel pattern
    result_queue = queue.Queue()
    stop_event = threading.Event()
    all_errors = []
    errors_lock = threading.Lock()

    def test_provider_sync(client: CloudProviderClient) -> None:
        """Test a provider in a thread (like Go goroutine)."""
        if stop_event.is_set():
            return

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
            finally:
                loop.close()
        except Exception as e:
            with errors_lock:
                all_errors.append(
                    f"Provider {client.get_type().value} detection failed: {e}"
                )
            if logger:
                logger.log(f"Provider {client.get_type().value} detection failed: {e}")

    # Start threads for each provider (like Go goroutines)
    threads = []
    for client in clients:
        thread = threading.Thread(target=test_provider_sync, args=(client,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Wait for first result or timeout (like Go select)
    try:
        result = result_queue.get(timeout=timeout)
        stop_event.set()  # Ensure all threads stop

        if logger:
            logger.log(f"Detected provider: {result.get_type().value}")
        return result

    except queue.Empty:
        # Timeout occurred
        stop_event.set()

        # Wait a bit for threads to finish
        for thread in threads:
            thread.join(timeout=0.1)

        raise CloudProviderNotFound(f"Provider detection timed out after {timeout}s")
