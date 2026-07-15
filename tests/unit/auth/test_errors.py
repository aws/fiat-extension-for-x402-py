# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for authentication error types."""

from __future__ import annotations

from fiat_extension_x402.auth import AuthenticationTimeoutError, ExpiredCredentialsError
from fiat_extension_x402.auth.errors import (
    AuthenticationError,
    InvalidCredentialsError,
    MissingCredentialsError,
)
from fiat_extension_x402.exceptions import AgentPayError


class TestAuthenticationError:
    def test_is_agent_pay_error(self) -> None:
        err = AuthenticationError("boom", "awsSigV4")
        assert isinstance(err, AgentPayError)
        assert err.auth_method == "awsSigV4"
        assert err.retryable is False
        assert err.code == "AUTHENTICATION_ERROR"

    def test_retryable_flag(self) -> None:
        err = AuthenticationError("boom", "awsSigV4", retryable=True)
        assert err.retryable is True


class TestInvalidCredentialsError:
    def test_message_without_details(self) -> None:
        err = InvalidCredentialsError("apiKey")
        assert str(err) == "Invalid credentials for apiKey"
        assert err.auth_method == "apiKey"
        assert err.retryable is False
        assert type(err).__name__ == "InvalidCredentialsError"

    def test_message_with_details(self) -> None:
        err = InvalidCredentialsError("oauth2", "token expired")
        assert str(err) == "Invalid credentials for oauth2: token expired"


class TestMissingCredentialsError:
    def test_message_includes_field(self) -> None:
        err = MissingCredentialsError("awsSigV4", "accessKeyId")
        assert "accessKeyId" in str(err)
        assert err.auth_method == "awsSigV4"


class TestExpiredCredentialsError:
    def test_attributes(self) -> None:
        err = ExpiredCredentialsError("oauth2", "token expired")
        assert err.retryable is True
        assert "expired" in str(err)


class TestAuthenticationTimeoutError:
    def test_attributes(self) -> None:
        err = AuthenticationTimeoutError("awsSigV4", "slow")
        assert err.retryable is True
        assert "timed out" in str(err)
