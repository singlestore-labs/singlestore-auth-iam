"""
SingleStore Auth IAM - Python Client Library

A Python client library for cloud provider identity detection and authentication
with SingleStore's IAM service.
"""

__version__ = "0.1.0"

from .api import detect_provider
from .jwt import get_jwt, get_jwt_database, get_jwt_api
from .models import (
    CloudIdentity,
    CloudProviderType,
    JWTType,
    NoCloudProviderDetectedError,
    ProviderNotDetectedError,
    ProviderDetectedNoIdentityError,
    AssumeRoleNotSupportedError,
)

__all__ = [
    "detect_provider",
    "get_jwt",
    "get_jwt_database", 
    "get_jwt_api",
    "CloudIdentity",
    "CloudProviderType",
    "JWTType",
    "NoCloudProviderDetectedError",
    "ProviderNotDetectedError",
    "ProviderDetectedNoIdentityError",
    "AssumeRoleNotSupportedError",
]
