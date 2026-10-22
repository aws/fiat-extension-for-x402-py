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


__all__ = [
    "AgenticCommerceError",
    "DPoPError",
    "SigningError",
    "ValidationError",
]
