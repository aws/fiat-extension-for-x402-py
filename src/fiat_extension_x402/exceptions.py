# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Error classes for the AWS Marketplace Agentic Commerce x402 extension."""

from __future__ import annotations

from typing import Any


class AgenticCommerceError(Exception):
    """Base error class for all errors raised by this package."""

    def __init__(
        self,
        message: str,
        code: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details


class ValidationError(AgenticCommerceError):
    """Error raised when input or configuration is invalid."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, "VALIDATION_ERROR", details)


class SigningError(AgenticCommerceError):
    """Error raised when quote token signing fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, "SIGNING_ERROR", details)


class DPoPError(AgenticCommerceError):
    """Error raised when a DPoP proof is invalid."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message, "DPOP_ERROR", details)


class SignatureError(AgenticCommerceError):
    """Error raised when a token signature cannot be verified."""

    def __init__(self, message: str, token_type: str) -> None:
        super().__init__(message, "SIGNATURE_ERROR", {"token_type": token_type})
        self.token_type = token_type


class ExpiryError(AgenticCommerceError):
    """Error raised when a token has expired."""

    def __init__(self, message: str, expiry: int, current_time: int) -> None:
        super().__init__(message, "EXPIRY_ERROR", {"expiry": expiry, "current_time": current_time})
        self.expiry = expiry
        self.current_time = current_time


class MismatchError(AgenticCommerceError):
    """Error raised when an expected value does not match the actual value."""

    def __init__(self, message: str, expected: str, actual: str) -> None:
        super().__init__(message, "MISMATCH_ERROR", {"expected": expected, "actual": actual})
        self.expected = expected
        self.actual = actual


__all__ = [
    "AgenticCommerceError",
    "DPoPError",
    "ExpiryError",
    "MismatchError",
    "SignatureError",
    "SigningError",
    "ValidationError",
]
