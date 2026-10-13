# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Type definitions for DPoP proof verification."""

from __future__ import annotations

from typing import Any, Protocol, TypedDict


class DPoPProofPayload(TypedDict, total=False):
    """Claims within a DPoP proof JWT."""

    jti: str
    htm: str
    htu: str
    iat: int
    ath: str
    nonce: str


class DPoPVerificationOptions(TypedDict, total=False):
    """Options for verifying a DPoP proof."""

    htm: str
    htu: str
    access_token: str | None
    max_age: int
    nonce_store: Any


class DPoPNonceStore(Protocol):
    """Protocol for tracking used DPoP proof identifiers (replay prevention)."""

    def has(self, jti: str) -> bool:
        """Return ``True`` if the proof id has already been seen."""
        ...  # pragma: no cover

    def add(self, jti: str, expires_at: int) -> None:
        """Record a proof id as used until ``expires_at`` (Unix time, seconds).

        ``has`` must return ``True`` for the id while the time is before
        ``expires_at``; the store may forget the id from then on.
        """
        ...  # pragma: no cover


__all__ = [
    "DPoPNonceStore",
    "DPoPProofPayload",
    "DPoPVerificationOptions",
]
