"""
Models and interfaces for the s2iam library.
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Protocol, Tuple
from typing import Any, Dict, Optional, Protocol, Type, TypeVar, Union


class CloudProviderType(Enum):
    """Cloud provider types."""
    AWS = "aws"
    GCP = "gcp" 
    AZURE = "azure"


class JWTType(Enum):
    """JWT token types."""
    DATABASE_ACCESS = "database"
    API_GATEWAY_ACCESS = "api"


@dataclass
class CloudIdentity:
    """Represents verified cloud identity information."""
    provider: CloudProviderType
    identifier: str
    account_id: str = ""
    region: str = ""
    resource_type: str = ""
    additional_claims: Dict[str, str] = field(default_factory=dict)


class Logger(Protocol):
    """Logger interface."""
    
    def log(self, message: str) -> None:
        """Log a message."""
        ...


class CloudProviderClient(ABC):
    """Abstract base class for cloud provider clients."""
    
    @abstractmethod
    async def detect(self) -> None:
        """
        Test if we are executing within this cloud provider.
        
        Raises:
            Exception: If provider is not detected or unavailable
        """
        ...
    
    @abstractmethod
    def get_type(self) -> CloudProviderType:
        """Return the cloud provider type."""
        ...
    
    @abstractmethod
    def assume_role(self, role_identifier: str) -> "CloudProviderClient":
        """
        Configure the provider to use an alternate identity.
        
        Args:
            role_identifier: Provider-specific role identifier
            
        Returns:
            New CloudProviderClient instance with assumed role
        """
        ...
    
    @abstractmethod
    async def get_identity_headers(
        self, 
        additional_params: Optional[Dict[str, str]] = None
    ) -> Tuple[Dict[str, str], CloudIdentity]:
        """
        Get headers needed to authenticate with the SingleStore auth service.
        
        Args:
            additional_params: Provider-specific parameters
            
        Returns:
            Tuple of (headers, identity)
            
        Raises:
            ProviderNotDetectedError: If detect() hasn't been called successfully
            ProviderDetectedNoIdentityError: If no identity is available
        """
        ...


# Exception classes
class S2IAMError(Exception):
    """Base exception for s2iam library."""
    pass


class NoCloudProviderDetectedError(S2IAMError):
    """Raised when no cloud provider can be detected."""
    pass


class ProviderNotDetectedError(S2IAMError):
    """Raised when attempting to use a provider that hasn't been detected."""
    pass


class ProviderDetectedNoIdentityError(S2IAMError):
    """Raised when a provider is detected but no identity is available."""
    pass


class AssumeRoleNotSupportedError(S2IAMError):
    """Raised when AssumeRole is called on a provider that doesn't support it."""
    pass
