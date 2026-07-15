# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Authentication error types."""

from __future__ import annotations

from typing import Optional

from fiat_extension_x402.exceptions import AgentPayError


class AuthenticationError(AgentPayError):
    """Base authentication error."""

    def __init__(
        self,
        message: str,
        auth_method: str,
        retryable: bool = False,
    ) -> None:
        super().__init__(
            message, "AUTHENTICATION_ERROR", {"auth_method": auth_method, "retryable": retryable}
        )
        self.auth_method = auth_method
        self.retryable = retryable


class InvalidCredentialsError(AuthenticationError):
    """Invalid credentials error."""

    def __init__(self, auth_method: str, details: Optional[str] = None) -> None:
        message = f"Invalid credentials for {auth_method}"
        if details:
            message = f"{message}: {details}"
        super().__init__(message, auth_method, False)


class MissingCredentialsError(AuthenticationError):
    """Missing credentials error."""

    def __init__(self, auth_method: str, missing_field: str) -> None:
        super().__init__(
            f"Missing required credential field for {auth_method}: {missing_field}",
            auth_method,
            False,
        )


class ExpiredCredentialsError(AuthenticationError):
    """Credentials have expired and must be refreshed."""

    def __init__(self, auth_method: str, details: Optional[str] = None) -> None:
        message = f"Credentials expired for {auth_method}"
        if details:
            message = f"{message}: {details}"
        super().__init__(message, auth_method, True)


class AuthenticationTimeoutError(AuthenticationError):
    """Authentication request timed out."""

    def __init__(self, auth_method: str, details: Optional[str] = None) -> None:
        message = f"Authentication timed out for {auth_method}"
        if details:
            message = f"{message}: {details}"
        super().__init__(message, auth_method, True)


__all__ = [
    "AuthenticationError",
    "AuthenticationTimeoutError",
    "ExpiredCredentialsError",
    "InvalidCredentialsError",
    "MissingCredentialsError",
]
