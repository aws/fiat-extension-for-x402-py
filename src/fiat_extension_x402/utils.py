# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Public utility functions for token handling and price parsing."""

from __future__ import annotations

import re
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


# Matches "$1.50", "1.50 USD", "1.50" — a non-negative decimal in ASCII digits with
# an optional leading "$" and an optional trailing 3-letter currency code (defaults
# to USD).
_MONEY_PATTERN = re.compile(r"^\$?([0-9]+\.?[0-9]*)\s*([A-Z]{3})?$")


def parse_money_to_decimal(money: str | float) -> dict[str, Any]:
    """Parse a monetary value to amount and currency.

    Supports formats: ``"$1.50"``, ``"1.50 USD"``, or numeric values (assumed USD).

    :param money: Monetary value in string or numeric form.
    :returns: Dict with ``amount`` (float) and ``currency`` (str).
    :raises ValidationError: if a string value does not match the expected format.
    """
    if isinstance(money, bool):
        raise ValidationError(f"Invalid money format: {money}")
    if isinstance(money, (int, float)):
        return {"amount": float(money), "currency": "USD"}

    match = _MONEY_PATTERN.match(money)
    if not match:
        raise ValidationError(f"Invalid money format: {money}")

    return {"amount": float(match.group(1)), "currency": match.group(2) or "USD"}


__all__ = [
    "decode_quote_token",
    "parse_money_to_decimal",
]
