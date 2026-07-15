# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for authenticator factory."""

from __future__ import annotations

import pytest
from botocore.credentials import Credentials  # type: ignore[import-untyped]

from fiat_extension_x402.auth import (
    ApiKeyAuthenticator,
    AwsSigV4Authenticator,
    CustomAuthenticator,
    OAuth2Authenticator,
    create_authenticator,
)
from fiat_extension_x402.auth.errors import InvalidCredentialsError


class TestCreateAuthenticator:
    def test_api_key(self) -> None:
        auth = create_authenticator({"type": "api-key", "apiKey": "test"})
        assert isinstance(auth, ApiKeyAuthenticator)

    def test_oauth2(self) -> None:
        auth = create_authenticator({"type": "oauth2", "accessToken": "tok"})
        assert isinstance(auth, OAuth2Authenticator)

    def test_custom(self) -> None:
        auth = create_authenticator({"type": "custom", "authenticate": lambda r: r})
        assert isinstance(auth, CustomAuthenticator)

    def test_unknown_type(self) -> None:
        with pytest.raises(InvalidCredentialsError):
            create_authenticator({"type": "magic"})

    def test_missing_type(self) -> None:
        with pytest.raises(InvalidCredentialsError):
            create_authenticator({})


class TestAuthFactoryAwsSigV4:
    """Cover the awsSigV4 branch in create_authenticator (line 44)."""

    def test_aws_sigv4_type(self) -> None:
        auth = create_authenticator(
            {
                "type": "awsSigV4",
                "credentials": Credentials("AKID", "secret", "tok"),
            }
        )
        assert isinstance(auth, AwsSigV4Authenticator)

    def test_factory_custom_non_callable(self) -> None:
        """Factory rejects custom type with non-callable authenticate (line 59)."""
        with pytest.raises(InvalidCredentialsError, match="authenticate must be callable"):
            create_authenticator({"type": "custom", "authenticate": "not-callable"})
