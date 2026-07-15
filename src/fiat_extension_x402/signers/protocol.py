# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Protocol definition for service-side Agent Pay signers."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ServiceAgentPaySigner(Protocol):
    """Protocol for service-side operations (quote token signing).

    Implementations sign quote token payloads as JWTs and expose the
    corresponding public key and service URL (issuer).
    """

    async def sign_quote(self, payload: dict[str, Any]) -> str:
        """Sign a quote token payload and return the compact JWT string.

        :param payload: Quote token claims to sign.
        :returns: Signed compact JWS (``header.payload.signature``).
        """
        ...  # pragma: no cover

    def get_public_key(self) -> object:
        """Return the public key for verification.

        The return type is implementation-defined (e.g., JWK dict, or an
        opaque handle when the key lives in a remote HSM).
        """
        ...  # pragma: no cover

    def get_service_url(self) -> str:
        """Return the service URL used as the ``iss`` claim in quote tokens."""
        ...  # pragma: no cover


__all__ = ["ServiceAgentPaySigner"]
