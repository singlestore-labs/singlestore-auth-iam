"""
SingleStore Auth IAM - Python Client Library

A Python client library for cloud provider identity detection and authentication
with SingleStore's IAM service.
"""

__version__ = "0.1.0"

from .api import DETECT_PROVIDER_DEFAULT_TIMEOUT, detect_provider
from .identity_format import (
    FORMAT_AWS_ARN,
    FORMAT_AWS_IAM_ROLE_ARN,
    FORMAT_AWS_ROLE_ID,
    FORMAT_AZURE_OBJECT_ID,
    FORMAT_AZURE_RESOURCE_ID,
    FORMAT_GCP_SA_EMAIL,
    FORMAT_GCP_SA_UNIQUE_ID,
    IDENTITY_FORMAT_PREFERENCE_ENV,
    IDENTITY_FORMAT_PREFERENCE_HEADER,
)
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
    "IDENTITY_FORMAT_PREFERENCE_HEADER",
    "IDENTITY_FORMAT_PREFERENCE_ENV",
    # The identity-format vocabulary, published so callers can name a preference
    # symbolically instead of hardcoding the tokens (parity with Go's models
    # package and Java's IdentityFormat).
    "FORMAT_AWS_ARN",
    "FORMAT_AWS_IAM_ROLE_ARN",
    "FORMAT_AWS_ROLE_ID",
    "FORMAT_GCP_SA_EMAIL",
    "FORMAT_GCP_SA_UNIQUE_ID",
    "FORMAT_AZURE_OBJECT_ID",
    "FORMAT_AZURE_RESOURCE_ID",
]
