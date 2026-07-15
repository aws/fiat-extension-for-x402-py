# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Error classes for the Agent Pay scheme."""

from __future__ import annotations

from typing import Any, Optional


class AgentPayError(Exception):
    """Base error class for all Agent Pay-related errors."""

    def __init__(
        self,
        message: str,
        code: str,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details


class ValidationError(AgentPayError):
    """Error thrown when validation fails."""

    def __init__(self, message: str, details: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message, "VALIDATION_ERROR", details)


class IdempotencyConflictError(AgentPayError):
    """Error thrown when a clientToken is reused with different request parameters.

    The same clientToken with the same parameters returns the cached response
    (idempotency). A different set of parameters triggers this error (HTTP 409).
    """

    def __init__(self, client_token: str, message: Optional[str] = None) -> None:
        super().__init__(
            message
            or f'Idempotency conflict: clientToken "{client_token}" was used with '
            "different parameters",
            "IDEMPOTENCY_CONFLICT",
            {"client_token": client_token},
        )
        self.client_token = client_token


class DPoPError(AgentPayError):
    """Error thrown when DPoP key generation or thumbprint computation fails."""

    def __init__(self, message: str, details: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message, "DPOP_ERROR", details)


class SignatureError(AgentPayError):
    """Error thrown when token signature verification fails."""

    def __init__(self, message: str, token_type: str) -> None:
        super().__init__(message, "SIGNATURE_ERROR", {"token_type": token_type})
        self.token_type = token_type


class ExpiryError(AgentPayError):
    """Error thrown when a token has expired."""

    def __init__(self, message: str, expiry: int, current_time: int) -> None:
        super().__init__(message, "EXPIRY_ERROR", {"expiry": expiry, "current_time": current_time})
        self.expiry = expiry
        self.current_time = current_time


class MismatchError(AgentPayError):
    """Error thrown when an expected value does not match the actual value."""

    def __init__(self, message: str, expected: str, actual: str) -> None:
        super().__init__(message, "MISMATCH_ERROR", {"expected": expected, "actual": actual})
        self.expected = expected
        self.actual = actual


__all__ = [
    "AgentPayError",
    "DPoPError",
    "ExpiryError",
    "IdempotencyConflictError",
    "MismatchError",
    "SignatureError",
    "ValidationError",
]
