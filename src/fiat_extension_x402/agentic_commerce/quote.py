# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Quote tokens: the seller's signed statement of what a request costs."""

from __future__ import annotations

import re
import uuid
from time import time
from typing import Any

from fiat_extension_x402.constants import (
    DEFAULT_QUOTE_VALIDITY_SECONDS,
    QUOTE_TOKEN_AUDIENCE,
    SCHEME_EXACT,
    SENTINEL_PAY_TO,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.signers.protocol import QuoteSigner

# Optional route details copied from ``extra`` into the quote when present.
_OPTIONAL_QUOTE_CLAIMS = ("description", "dimensions", "support", "terms")

# The payment service rejects prices with more decimal places than this.
_MAX_PRICE_DECIMAL_PLACES = 8

_ASSET_PREFIX = "iso4217:"

# The amount and asset of an ``{amount, asset}`` price, matched in full: a plain
# non-negative decimal in ASCII digits, and ``iso4217:`` with an upper-case
# three-letter code, the asset a string price becomes.
_AMOUNT_PATTERN = re.compile(r"[0-9]+(?:\.([0-9]+))?")
_ASSET_PATTERN = re.compile(r"iso4217:[A-Z]{3}")


def _check_asset_amount(amount: object, asset: object) -> tuple[str, str]:
    """Check the amount and asset of an ``{amount, asset}`` route price.

    The amount must be a plain non-negative decimal string (``"0.50"``, never
    ``"$0.50"``, ``" 0.50"`` or ``"5e-1"``) with at most 8 decimal places, as for a
    string price. The asset must be ``iso4217:`` and an upper-case three-letter
    code. Error messages show the amount and asset alone.

    :param amount: The price's amount.
    :param asset: The price's asset.
    :returns: The amount and asset, once checked.
    :raises ValidationError: if the amount or asset is not a string or is
        malformed, or the amount has more than 8 decimal places.
    """

    def shown() -> str:
        try:
            return repr({"amount": amount, "asset": asset})
        except Exception:  # noqa: BLE001 - e.g. an int over the str digit limit
            return "(not representable)"

    match = _AMOUNT_PATTERN.fullmatch(amount) if isinstance(amount, str) else None
    if (
        match is None
        or not isinstance(amount, str)  # Implied by match; narrows amount for mypy.
        or not isinstance(asset, str)
        or not _ASSET_PATTERN.fullmatch(asset)
    ):
        raise ValidationError(f"Invalid price: {shown()}")
    if len(match.group(1) or "") > _MAX_PRICE_DECIMAL_PLACES:
        raise ValidationError(
            f"Price may have at most {_MAX_PRICE_DECIMAL_PLACES} decimal places: {shown()}"
        )
    return amount, asset


def _check_scheme_network(scheme: object, network: object) -> tuple[str, str]:
    """The requirements' scheme and network, which every quote must carry."""
    if scheme != SCHEME_EXACT:
        raise ValidationError(f"Quote scheme must be {SCHEME_EXACT!r}, got {scheme!r}")
    if not isinstance(network, str) or not network:
        raise ValidationError(f"Quote network must be a non-empty string, got {network!r}")
    return SCHEME_EXACT, network


def enhance_payment_requirements(
    payment_requirements: dict[str, Any],
    signer: QuoteSigner,
) -> dict[str, Any]:
    """Sign a quote token for the requirements and embed it in ``extra.quoteToken``.

    ``payTo`` is the seller's AWS Marketplace product ID. It is signed into the
    quote as ``payTo`` and as ``settlement.product_id``, which the payment service
    requires to settle the payment against the listing. Other ``settlement``
    fields can be supplied in ``extra.settlement``.

    The requirements' ``scheme`` and ``network`` are signed into the quote as
    claims of the same names, so the payment service, which sees only the quote,
    can check what kind of payment the seller priced. Both are required, and the
    scheme must be ``exact``.

    The returned requirements carry the sentinel ``payTo`` and a
    ``maxTimeoutSeconds`` equal to the quote's validity: the signed quote is the
    authoritative source for both.

    :param payment_requirements: Base x402 payment requirements (wire field names).
    :param signer: Signer for the quote token. Its service URL becomes ``iss``.
    :returns: Enhanced payment requirements.
    :raises ValidationError: if the signer's service URL or ``payTo`` is empty, the
        amount or asset is not one ``parse_price`` returns, the scheme is not
        ``exact``, the network is missing, or ``extra.settlement.product_id``
        disagrees with ``payTo``.
    """
    issuer = signer.get_service_url()
    if not issuer or not issuer.strip():
        raise ValidationError(
            "Cannot sign quote token: signer service URL (issuer) is empty. "
            "Configure a non-empty service_url on the signer; it becomes the quote "
            "token's 'iss' claim, which the service requires."
        )

    # The price is checked again where it is signed, for a caller that skips
    # parse_price.
    amount, asset = _check_asset_amount(
        payment_requirements.get("amount"), payment_requirements.get("asset")
    )

    scheme, network = _check_scheme_network(
        payment_requirements.get("scheme"), payment_requirements.get("network")
    )

    product_id = str(payment_requirements.get("payTo") or "").strip()
    if not product_id:
        raise ValidationError("payTo must be the seller's AWS Marketplace product ID")

    extra: dict[str, Any] = dict(payment_requirements.get("extra") or {})
    settlement: dict[str, Any] = dict(extra.get("settlement") or {})
    if settlement.setdefault("product_id", product_id) != product_id:
        raise ValidationError(
            "extra.settlement.product_id must match payTo (the AWS Marketplace product ID)"
        )
    now = int(time())
    validity = payment_requirements.get("maxTimeoutSeconds") or DEFAULT_QUOTE_VALIDITY_SECONDS

    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": QUOTE_TOKEN_AUDIENCE,
        "iat": now,
        "exp": now + validity,
        "jti": str(uuid.uuid4()),
        "price": {
            "amount": amount,
            "currency": asset[len(_ASSET_PREFIX) :],
        },
        "scheme": scheme,
        "network": network,
        "payTo": product_id,
        "reference": extra.get("reference") or "RESOURCE",
        "settlement": settlement,
    }
    for name in _OPTIONAL_QUOTE_CLAIMS:
        if extra.get(name) is not None:
            claims[name] = extra[name]

    extra["quoteToken"] = signer.sign_quote(claims)
    return {
        **payment_requirements,
        "payTo": SENTINEL_PAY_TO,
        "maxTimeoutSeconds": claims["exp"] - claims["iat"],
        "extra": extra,
    }


__all__ = ["enhance_payment_requirements"]
