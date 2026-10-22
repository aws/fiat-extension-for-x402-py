# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Public utility functions for token handling."""

from __future__ import annotations

from typing import Any

import jwt as pyjwt

from fiat_extension_x402.exceptions import ValidationError


def decode_quote_token(token: str) -> dict[str, Any]:
    """Decode a quote token JWT without signature verification.

    For inspection only: the claims are not trusted. Verify payments with
    :class:`~fiat_extension_x402.AgenticCommerceVerifier`.

    :param token: Quote token JWT string.
    :returns: Decoded claims dict.
    :raises ValidationError: if the token is malformed.
    """
    try:
        claims: dict[str, Any] = pyjwt.decode(token, options={"verify_signature": False})
        return claims
    except Exception as exc:
        raise ValidationError(f"Invalid quote token format: {exc}") from exc


__all__ = [
    "decode_quote_token",
]
