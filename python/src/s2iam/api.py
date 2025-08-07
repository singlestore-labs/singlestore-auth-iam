"""
Main API for the s2iam library.
"""

import asyncio
import os
from typing import Dict, List, Optional

from .aws import new_client as new_aws_client
from .azure import new_client as new_azure_client
from .gcp import new_client as new_gcp_client
from .models import (
    CloudProviderClient,
    Logger,
    NoCloudProviderDetectedError,
)


class DefaultLogger:
    """Default logger implementation."""
    
    def log(self, message: str) -> None:
        """Log a message to stdout."""
        print(f"[s2iam] {message}")


async def detect_provider(
    timeout: float = 5.0,
    logger: Optional[Logger] = None,
    clients: Optional[List[CloudProviderClient]] = None
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
        NoCloudProviderDetectedError: If no provider can be detected
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
    
    # Use asyncio to test providers concurrently
    async def test_provider(client: CloudProviderClient) -> Optional[CloudProviderClient]:
        try:
            await client.detect()
            return client
        except Exception as e:
            if logger:
                logger.log(f"Provider {client.get_type().value} detection failed: {e}")
            return None
    
    # Run detection with timeout
    try:
        tasks = [asyncio.create_task(test_provider(client)) for client in clients]
        done, pending = await asyncio.wait_for(
            asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED),
            timeout=timeout
        )
        
        # Cancel pending tasks
        for task in pending:
            task.cancel()
        
        # Check results
        for task in done:
            result = await task
            if result is not None:
                if logger:
                    logger.log(f"Detected provider: {result.get_type().value}")
                return result
        
        # No provider detected
        raise NoCloudProviderDetectedError("No cloud provider detected")
        
    except asyncio.TimeoutError:
        raise NoCloudProviderDetectedError(f"Provider detection timed out after {timeout}s")
