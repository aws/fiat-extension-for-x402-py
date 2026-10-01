# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Seller side of the ``exact`` scheme on AWS Marketplace Agentic Commerce networks.

Register it on an x402 resource server; x402 core then calls it to price each
route, to add a signed quote token to every 402 response, and before each
payment is verified (where it checks DPoP proofs)::

    from x402 import x402ResourceServer
    server = x402ResourceServer(facilitator_client)
    server.register("aws:base", ExactAgenticCommerceServerScheme(signer=signer))
"""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any, Optional

import jwt
from x402.schemas import AbortResult, AssetAmount, PaymentRequirements, Price, SupportedKind
from x402.schemas.hooks import VerifyContext

from fiat_extension_x402.agentic_commerce.quote import enhance_payment_requirements
from fiat_extension_x402.constants import (
    AGENTIC_COMMERCE_CAIP_FAMILY,
    ASSET_TRANSFER_METHOD,
    DEFAULT_ASSET,
    DYNAMIC_EXTRA_FIELDS,
    SCHEME_EXACT,
)
from fiat_extension_x402.dpop.types import DPoPNonceStore
from fiat_extension_x402.dpop.verification import extract_dpop_thumbprint, verify_dpop_proof
from fiat_extension_x402.exceptions import DPoPError, ValidationError
from fiat_extension_x402.signers.protocol import QuoteSigner

# "$1.50", "1.50 USD", "1.50": a non-negative decimal with an optional leading
# "$" and an optional trailing ISO 4217 code (defaults to USD).
_MONEY_PATTERN = re.compile(r"^\$?(\d+(?:\.\d+)?)\s*([A-Z]{3})?$")

_DEFAULT_DPOP_MAX_AGE_SECONDS = 60


class ExactAgenticCommerceScheme:
    """``exact`` server scheme for AWS Marketplace Agentic Commerce.

    :param signer: Signs quote tokens. Its service URL becomes the quote's ``iss``.
    :param dpop_nonce_store: Optional store of seen DPoP proof ids, to reject
        replayed proofs.
    :param dpop_max_age_seconds: Maximum age of a DPoP proof.
    """

    scheme = SCHEME_EXACT
    caip_family = AGENTIC_COMMERCE_CAIP_FAMILY
    default_asset_transfer_method = ASSET_TRANSFER_METHOD
    # Verify before the handler runs; settlement after it is a no-op because the
    # service captures the payment when it issues the payment token.
    payment_flows = {
        ASSET_TRANSFER_METHOD: {"supported": ("authorization",), "default": "authorization"},
    }
    # The quote token is signed fresh for every 402, so x402 core ignores it when
    # matching a buyer's ``accepted`` requirements against the route's. The
    # facilitator checks the quote instead.
    dynamic_extra_fields = DYNAMIC_EXTRA_FIELDS

    def __init__(
        self,
        *,
        signer: QuoteSigner,
        dpop_nonce_store: Optional[DPoPNonceStore] = None,
        dpop_max_age_seconds: int = _DEFAULT_DPOP_MAX_AGE_SECONDS,
    ) -> None:
        self._signer = signer
        self._dpop_nonce_store = dpop_nonce_store
        self._dpop_max_age_seconds = dpop_max_age_seconds

    @property
    def signer(self) -> QuoteSigner:
        """The quote token signer."""
        return self._signer

    def parse_price(self, price: Price, network: str) -> AssetAmount:
        """Convert a route price into a fiat amount and ISO 4217 asset.

        Amounts are decimal strings (``"0.50"``), not atomic units.

        :param price: ``"$1.50"``, ``"1.50 USD"``, ``1.50``, or an ``AssetAmount``.
        :param network: Target network (pricing does not depend on it).
        :raises ValidationError: if the price cannot be parsed.
        """
        if isinstance(price, AssetAmount):
            return price
        if isinstance(price, dict):
            return AssetAmount.model_validate(price)
        if isinstance(price, (int, float)):
            amount, currency = str(price), "USD"
        else:
            match = _MONEY_PATTERN.match(str(price).strip())
            if not match:
                raise ValidationError(f"Invalid price: {price!r}")
            amount, currency = match.group(1), match.group(2) or "USD"
        value = Decimal(amount)  # Always parses: a str(number) or a regex-matched decimal.
        if not value.is_finite() or value < 0:
            raise ValidationError(f"Price must be a finite, non-negative amount: {price!r}")
        if isinstance(price, (int, float)):
            # Plain decimal notation, never exponent form ("1E-7").
            amount = format(value, "f")
        asset = f"iso4217:{currency}" if currency != "USD" else DEFAULT_ASSET
        return AssetAmount(amount=amount, asset=asset, extra={})

    def enhance_payment_requirements(
        self,
        requirements: PaymentRequirements,
        supported_kind: Optional[SupportedKind] = None,
        extensions: Optional[list[str]] = None,
    ) -> PaymentRequirements:
        """Sign a quote token for the requirements and embed it in ``extra.quoteToken``."""
        base: dict[str, Any] = requirements.model_dump(by_alias=True, exclude_none=True)
        return PaymentRequirements.model_validate(enhance_payment_requirements(base, self._signer))

    def before_verify(self, context: VerifyContext) -> Optional[AbortResult]:
        """Check the DPoP proof of a DPoP-bound payment token.

        A payment token bound to a key (``cnf.jkt``) is accepted only with a
        ``DPoP`` header proving possession of that key, for this request's method
        and URL, over this payment token. The token's signature is verified
        afterwards by the facilitator, so a token whose binding was altered fails
        there.
        """
        payment_token = (getattr(context.payment_payload, "payload", None) or {}).get(
            "paymentToken"
        )
        if not isinstance(payment_token, str) or not payment_token:
            return None
        try:
            cnf = jwt.decode(payment_token, options={"verify_signature": False}).get("cnf")
        except jwt.PyJWTError:
            return None  # Malformed token: rejected by the facilitator.
        if not isinstance(cnf, dict) or "jkt" not in cnf:
            return None

        request = getattr(context.transport_context, "request", None)
        adapter = getattr(request, "adapter", None)
        if adapter is None:
            return AbortResult(reason="dpop_required")
        proof = adapter.get_header("DPoP") or adapter.get_header("dpop")
        if not proof:
            return AbortResult(reason="dpop_required")
        try:
            if extract_dpop_thumbprint(proof) != cnf["jkt"]:
                return AbortResult(reason="dpop_invalid")
            verify_dpop_proof(
                proof,
                {
                    "htm": adapter.get_method().upper(),
                    "htu": adapter.get_url().split("?", 1)[0].split("#", 1)[0],
                    "access_token": payment_token,
                    "max_age": self._dpop_max_age_seconds,
                    "nonce_store": self._dpop_nonce_store,
                },
            )
        except DPoPError:
            return AbortResult(reason="dpop_invalid")
        return None


__all__ = ["ExactAgenticCommerceScheme"]
