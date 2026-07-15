# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Factory for creating authenticators from configuration dicts."""

from __future__ import annotations

from typing import Any, Union

from fiat_extension_x402.auth.api_key import ApiKeyAuthenticator
from fiat_extension_x402.auth.aws_sigv4 import AwsSigV4Authenticator
from fiat_extension_x402.auth.custom import CustomAuthenticator
from fiat_extension_x402.auth.errors import InvalidCredentialsError
from fiat_extension_x402.auth.oauth2 import OAuth2Authenticator


def create_authenticator(
    config: dict[str, Any],
) -> Union[ApiKeyAuthenticator, AwsSigV4Authenticator, OAuth2Authenticator, CustomAuthenticator]:
    """Create an authenticator from a configuration dict.

    The ``type`` key determines which authenticator is constructed:

    - ``"api-key"``: requires ``apiKey``, optional ``headerName``, ``prefix``
    - ``"awsSigV4"``: requires ``credentials``
    - ``"oauth2"``: requires ``accessToken``, optional ``onRefresh``
    - ``"custom"``: requires ``authenticate`` (callable)

    :param config: Configuration dict with ``type`` and strategy-specific keys.
    :returns: An authenticator instance.
    :raises InvalidCredentialsError: if ``type`` is missing or unsupported.
    """
    auth_type = config.get("type")
    if not auth_type:
        raise InvalidCredentialsError("unknown", "config must include a 'type' field")

    if auth_type == "api-key":
        return ApiKeyAuthenticator(
            config.get("apiKey", ""),
            header_name=config.get("headerName", "X-API-Key"),
            prefix=config.get("prefix"),
        )

    if auth_type == "awsSigV4":
        return AwsSigV4Authenticator(
            config.get("credentials"),
            region=config.get("region", "us-east-1"),
            service=config.get("service", "aws-marketplace"),
        )

    if auth_type == "oauth2":
        return OAuth2Authenticator(
            config.get("accessToken", ""),
            on_refresh=config.get("onRefresh"),
        )

    if auth_type == "custom":
        authenticate_fn = config.get("authenticate")
        if not callable(authenticate_fn):
            raise InvalidCredentialsError("custom", "authenticate must be callable")
        # The CustomAuthenticator expects Callable[[SignedRequest], SignedRequest] but
        # we trust the factory caller here to provide the right type.
        return CustomAuthenticator(authenticate_fn)

    raise InvalidCredentialsError(auth_type, f"Unsupported authenticator type: {auth_type}")


__all__ = ["create_authenticator"]
