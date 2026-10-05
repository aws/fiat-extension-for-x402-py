# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Protocol for quote token signers."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class QuoteSigner(Protocol):
    """Signs the seller's quote tokens.

    Implementations sign quote token claims as a compact JWS and expose the
    service URL that becomes the token's ``iss`` claim.
    """

    def sign_quote(self, payload: dict[str, Any]) -> str:
        """Sign quote token claims and return the compact JWS.

        :param payload: Quote token claims to sign.
        :returns: Signed compact JWS (``header.payload.signature``).
        """
        ...  # pragma: no cover

    def get_service_url(self) -> str:
        """Return the service URL used as the ``iss`` claim in quote tokens."""
        ...  # pragma: no cover


__all__ = ["QuoteSigner"]
