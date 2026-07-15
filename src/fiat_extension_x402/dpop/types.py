# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Type definitions for DPoP proof creation and verification."""

from __future__ import annotations

from typing import Any, Optional, Protocol, TypedDict


class DPoPProofPayload(TypedDict, total=False):
    """Claims within a DPoP proof JWT."""

    jti: str
    htm: str
    htu: str
    iat: int
    ath: str
    nonce: str


class DPoPProofOptions(TypedDict, total=False):
    """Options for creating a DPoP proof."""

    htm: str
    htu: str
    access_token: Optional[str]
    nonce: Optional[str]


class DPoPVerificationOptions(TypedDict, total=False):
    """Options for verifying a DPoP proof."""

    htm: str
    htu: str
    access_token: Optional[str]
    max_age: int
    nonce_store: Any


class DPoPNonceStore(Protocol):
    """Protocol for tracking used DPoP proof identifiers (replay prevention)."""

    def has(self, jti: str) -> bool:
        """Return ``True`` if the proof id has already been seen."""
        ...  # pragma: no cover

    def add(self, jti: str, expires_at: int) -> None:
        """Record a proof id as used, with an expiry timestamp (seconds)."""
        ...  # pragma: no cover


__all__ = [
    "DPoPNonceStore",
    "DPoPProofOptions",
    "DPoPProofPayload",
    "DPoPVerificationOptions",
]
