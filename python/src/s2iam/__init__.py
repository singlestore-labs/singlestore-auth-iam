"""
SingleStore Auth IAM - Python Client Library

A Python client library for cloud provider identity detection and authentication
with SingleStore's IAM service.
"""

__version__ = "0.1.0"

from .api import DETECT_PROVIDER_DEFAULT_TIMEOUT, detect_provider
from .jwt import get_jwt, get_jwt_api, get_jwt_database
from .models import (
    AssumeRoleNotSupported,
    CloudIdentity,
    CloudProviderNotFound,
    CloudProviderType,
    JWTType,
    ProviderIdentityUnavailable,
    ProviderNotDetected,
)

__all__ = [
    "detect_provider",
    "DETECT_PROVIDER_DEFAULT_TIMEOUT",
    "get_jwt",
    "get_jwt_database",
    "get_jwt_api",
    "CloudIdentity",
    "CloudProviderType",
    "JWTType",
    "CloudProviderNotFound",
    "ProviderNotDetected",
    "ProviderIdentityUnavailable",
    "AssumeRoleNotSupported",
]
