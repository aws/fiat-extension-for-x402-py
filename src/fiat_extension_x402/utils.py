# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Public utility functions for token handling and price parsing."""

from __future__ import annotations

import re
import time
from typing import Any

import jwt as pyjwt

from fiat_extension_x402.exceptions import ExpiryError, SignatureError, ValidationError
from fiat_extension_x402.security import ALLOWED_ALGORITHMS


def decode_quote_token(token: str) -> dict[str, Any]:
    """Decode a quote token JWT without signature verification.

    :param token: Quote token JWT string.
    :returns: Decoded claims dict.
    :raises ValidationError: if the token is malformed.
    """
    try:
        claims: dict[str, Any] = pyjwt.decode(token, options={"verify_signature": False})
        return claims
    except Exception as exc:
        raise ValidationError(f"Invalid quote token format: {exc}") from exc


def verify_quote_token(token: str, public_key: Any) -> dict[str, Any]:
    """Verify a quote token JWT signature and expiry.

    :param token: Quote token JWT string.
    :param public_key: Public key for verification (PyJWT-compatible).
    :returns: Verified claims dict.
    :raises SignatureError: if signature verification fails.
    :raises ExpiryError: if the token has expired.
    """
    try:
        claims: dict[str, Any] = pyjwt.decode(
            token,
            public_key,
            algorithms=ALLOWED_ALGORITHMS,
            options={"verify_exp": False, "verify_aud": False},
        )
    except pyjwt.InvalidSignatureError as exc:
        raise SignatureError(f"Quote token signature invalid: {exc}", "quote") from exc
    except pyjwt.PyJWTError as exc:
        raise SignatureError(f"Quote token verification failed: {exc}", "quote") from exc

    exp = claims.get("exp")
    if exp is not None:
        now = int(time.time())
        if exp < now:
            raise ExpiryError("Quote token expired", exp, now)

    return claims


def verify_payment_token(token: str, public_key: Any) -> dict[str, Any]:
    """Verify a payment token JWT signature and expiry.

    :param token: Payment token JWT string.
    :param public_key: Public key for verification (PyJWT-compatible).
    :returns: Verified claims dict.
    :raises SignatureError: if signature verification fails.
    :raises ExpiryError: if the token has expired.
    """
    try:
        claims: dict[str, Any] = pyjwt.decode(
            token,
            public_key,
            algorithms=ALLOWED_ALGORITHMS,
            options={"verify_exp": False, "verify_aud": False},
        )
    except pyjwt.InvalidSignatureError as exc:
        raise SignatureError(f"Payment token signature invalid: {exc}", "payment") from exc
    except pyjwt.PyJWTError as exc:
        raise SignatureError(f"Payment token verification failed: {exc}", "payment") from exc

    exp = claims.get("exp")
    if exp is not None:
        now = int(time.time())
        if exp < now:
            raise ExpiryError("Payment token expired", exp, now)

    return claims


# Matches "$1.50", "1.50 USD", "1.50" — a non-negative decimal with an optional
# leading "$" and an optional trailing 3-letter currency code (defaults to USD).
_MONEY_PATTERN = re.compile(r"^\$?(\d+\.?\d*)\s*([A-Z]{3})?$")


def parse_money_to_decimal(money: str | float) -> dict[str, Any]:
    """Parse a monetary value to amount and currency.

    Supports formats: ``"$1.50"``, ``"1.50 USD"``, or numeric values (assumed USD).

    :param money: Monetary value in string or numeric form.
    :returns: Dict with ``amount`` (float) and ``currency`` (str).
    :raises ValidationError: if a string value does not match the expected format.
    """
    if isinstance(money, (int, float)):
        return {"amount": float(money), "currency": "USD"}

    match = _MONEY_PATTERN.match(money)
    if not match:
        raise ValidationError(f"Invalid money format: {money}")

    return {"amount": float(match.group(1)), "currency": match.group(2) or "USD"}


__all__ = [
    "decode_quote_token",
    "parse_money_to_decimal",
    "verify_payment_token",
    "verify_quote_token",
]
