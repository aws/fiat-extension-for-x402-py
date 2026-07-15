# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Authentication for client-to-Agent-Pay communication.

Provides a small :class:`Authenticator` protocol and an AWS SigV4 implementation
that signs outgoing requests. The client uses an authenticator to attach the
necessary headers before sending a request to the Agent Pay Service.
"""

from fiat_extension_x402.auth.api_key import ApiKeyAuthenticator
from fiat_extension_x402.auth.aws_sigv4 import AwsSigV4Authenticator, create_env_credential_provider
from fiat_extension_x402.auth.custom import CustomAuthenticator
from fiat_extension_x402.auth.errors import (
    AuthenticationError,
    AuthenticationTimeoutError,
    ExpiredCredentialsError,
    InvalidCredentialsError,
    MissingCredentialsError,
)
from fiat_extension_x402.auth.factory import create_authenticator
from fiat_extension_x402.auth.oauth2 import OAuth2Authenticator
from fiat_extension_x402.auth.types import Authenticator, SignedRequest

__all__ = [
    "ApiKeyAuthenticator",
    "AuthenticationError",
    "AuthenticationTimeoutError",
    "Authenticator",
    "AwsSigV4Authenticator",
    "CustomAuthenticator",
    "ExpiredCredentialsError",
    "InvalidCredentialsError",
    "MissingCredentialsError",
    "OAuth2Authenticator",
    "SignedRequest",
    "create_authenticator",
    "create_env_credential_provider",
]
