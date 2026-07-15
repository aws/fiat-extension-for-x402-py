# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Public utility functions for token handling, transaction IDs, and JWKS fetching."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Optional, Union

import httpx
import jwt as pyjwt

from fiat_extension_x402.exceptions import ExpiryError, SignatureError, ValidationError
from fiat_extension_x402.security import ALLOWED_ALGORITHMS

# JWKS cache: url -> (jwks_data, fetched_at)
_jwks_cache: dict[str, tuple[Any, float]] = {}
_JWKS_CACHE_TTL_SECONDS = 3600


def decode_quote_token(token: str) -> dict[str, Any]:
    """Decode a quote token JWT without signature verification.

    :param token: Quote token JWT string.
    :returns: Decoded claims dict.
    :raises ValidationError: if the token is malformed.
    """
    try:
        claims: dict[str, Any] = pyjwt.decode(token, options={"verify_signature": False})
        return claims
    except Exception as exc:  # noqa: BLE001
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


def extract_quote_from_payment(payment: dict[str, Any]) -> str:
    """Extract the quote token from a payment token's claims.

    Looks for ``quote_token`` at the top level, then in ``payment_context.quote_token``.

    :param payment: Payment token claims dict.
    :returns: The quote token string.
    """
    qt = payment.get("quote_token")
    if qt:
        return str(qt)
    pc = payment.get("payment_context")
    if isinstance(pc, dict):
        val = pc.get("quote_token", "")
        return str(val)
    return ""


def generate_transaction_id(network: str, agent_pay_id: str) -> str:
    """Generate a transaction ID.

    Format: ``{network}:{uuid16chars}``

    :param network: Network identifier.
    :param agent_pay_id: Agent Pay identifier (unused but reserved).
    :returns: Transaction ID string.
    """
    short_id = uuid.uuid4().hex[:16]
    return f"{network}:{short_id}"


# Matches "$1.50", "1.50 USD", "1.50" — a non-negative decimal with an optional
# leading "$" and an optional trailing 3-letter currency code (defaults to USD).
_MONEY_PATTERN = re.compile(r"^\$?(\d+\.?\d*)\s*([A-Z]{3})?$")


def parse_money_to_decimal(money: Union[str, int, float]) -> dict[str, Any]:
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


def parse_transaction_id(transaction_id: str) -> dict[str, str]:
    """Parse a transaction ID into network and id components.

    The last ``:``-delimited segment is the id; everything before is the network.

    :param transaction_id: Transaction ID string.
    :returns: Dict with ``network`` and ``id`` keys.
    :raises ValidationError: if the format is invalid.
    """
    idx = transaction_id.rfind(":")
    if idx < 0:
        raise ValidationError(f"Invalid transaction ID format: {transaction_id}")
    network = transaction_id[:idx]
    id_part = transaction_id[idx + 1 :]
    if not network or not id_part:
        raise ValidationError(f"Invalid transaction ID format: {transaction_id}")
    return {"network": network, "id": id_part}


def format_transaction_id(network: str, id: str) -> str:
    """Format a network and id into a transaction ID.

    :param network: Network identifier (must contain ``:``)
    :param id: Transaction id component.
    :returns: Formatted transaction ID.
    :raises ValidationError: if network does not contain ``:``.
    """
    if ":" not in network:
        raise ValidationError(f"Network must be in scheme:provider format: {network}")
    return f"{network}:{id}"


def is_valid_transaction_id(transaction_id: str) -> bool:
    """Check if a string is a valid transaction ID.

    :param transaction_id: Value to check.
    :returns: ``True`` if valid, ``False`` otherwise.
    """
    try:
        parse_transaction_id(transaction_id)
        return True
    except ValidationError:
        return False


def extract_network_from_transaction_id(transaction_id: str) -> str:
    """Extract the network from a transaction ID.

    :param transaction_id: Transaction ID string.
    :returns: Network component.
    :raises ValidationError: if the format is invalid.
    """
    return parse_transaction_id(transaction_id)["network"]


def fetch_service_jwks(service_url: str) -> Any:
    """Fetch a service's JWKS with 1-hour caching.

    :param service_url: Base URL of the service (JWKS fetched from
        ``{service_url}/.well-known/jwks.json``).
    :returns: Parsed JWKS dict.
    :raises ValidationError: if the fetch fails.
    """
    url = f"{service_url.rstrip('/')}/.well-known/jwks.json"
    cached = _jwks_cache.get(url)
    if cached is not None and (time.time() - cached[1]) < _JWKS_CACHE_TTL_SECONDS:
        return cached[0]

    with httpx.Client() as client:
        response = client.get(url)

    if response.status_code != 200:
        raise ValidationError(f"Failed to fetch JWKS from {url}: {response.reason_phrase}")

    data = response.json()
    _jwks_cache[url] = (data, time.time())
    return data


def clear_service_jwks_cache(service_url: Optional[str] = None) -> None:
    """Clear the JWKS cache.

    :param service_url: If provided, clear only this service's cache entry.
        If ``None``, clear the entire cache.
    """
    if service_url is None:
        _jwks_cache.clear()
    else:
        url = f"{service_url.rstrip('/')}/.well-known/jwks.json"
        _jwks_cache.pop(url, None)


__all__ = [
    "clear_service_jwks_cache",
    "decode_quote_token",
    "extract_network_from_transaction_id",
    "extract_quote_from_payment",
    "fetch_service_jwks",
    "format_transaction_id",
    "generate_transaction_id",
    "is_valid_transaction_id",
    "parse_money_to_decimal",
    "parse_transaction_id",
    "verify_payment_token",
    "verify_quote_token",
]
