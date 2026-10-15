# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Seller side of the ``exact`` scheme on AWS Marketplace Agentic Commerce networks.

Register it on an x402 resource server; x402 core then calls it to price each
route, to add a signed quote token to every 402 response, and before and after
each payment is verified (where it checks DPoP proofs)::

    from x402 import x402ResourceServer
    server = x402ResourceServer(facilitator_client)
    server.register("aws:base", ExactAgenticCommerceServerScheme(signer=signer))
"""

from __future__ import annotations

import logging
import re
import time
import weakref
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import Any, cast

import jwt
import pydantic
from x402.schemas import AbortResult, AssetAmount, PaymentRequirements, Price, SupportedKind
from x402.schemas.hooks import VerifyContext, VerifyResultContext

from fiat_extension_x402.agentic_commerce.quote import (
    _MAX_PRICE_DECIMAL_PLACES,
    _check_asset_amount,
    enhance_payment_requirements,
)
from fiat_extension_x402.constants import (
    AGENTIC_COMMERCE_CAIP_FAMILY,
    ASSET_TRANSFER_METHOD,
    DEFAULT_ASSET,
    DYNAMIC_EXTRA_FIELDS,
    SCHEME_EXACT,
)
from fiat_extension_x402.dpop.types import DPoPNonceStore
from fiat_extension_x402.dpop.verification import (
    _replay_expires_at,
    extract_dpop_thumbprint,
    verify_dpop_proof,
)
from fiat_extension_x402.exceptions import DPoPError, ValidationError
from fiat_extension_x402.signers.protocol import QuoteSigner

# "$1.50", "1.50 USD", "1.50": a non-negative decimal in ASCII digits with an
# optional leading "$" and an optional trailing ISO 4217 code (defaults to USD).
_MONEY_PATTERN = re.compile(r"^\$?([0-9]+(?:\.[0-9]+)?)\s*([A-Z]{3})?$")

_DEFAULT_DPOP_MAX_AGE_SECONDS = 60

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _PendingProof:
    """A DPoP proof checked by ``before_verify``, not yet recorded."""

    jti: str
    expires_at: int


class _PendingProofs:
    """Proofs checked by ``before_verify``, by transport context, until ``after_verify``.

    x402 core builds a new transport context for each request and passes the same
    one to both hooks. It is keyed by identity (x402's is an unhashable dataclass)
    and held weakly, so a request that never reaches ``after_verify`` (the
    facilitator rejects the token, or another hook aborts) leaves nothing behind.
    """

    def __init__(self) -> None:
        self._by_id: dict[int, tuple[weakref.ref[Any], _PendingProof]] = {}

    def set(self, transport_context: object, proof: _PendingProof) -> None:
        """Keep ``proof`` for ``transport_context``.

        :raises TypeError: if ``transport_context`` cannot be weakly referenced.
        """
        key = id(transport_context)
        # An id is reused only once its object is gone, and so its entry with it.
        ref = weakref.ref(transport_context, lambda _: self._by_id.pop(key, None))
        self._by_id[key] = (ref, proof)

    def pop(self, transport_context: object) -> _PendingProof | None:
        """Remove and return the proof kept for ``transport_context``, if any."""
        entry = self._by_id.get(id(transport_context))
        if entry is None or entry[0]() is not transport_context:
            return None
        del self._by_id[id(transport_context)]
        return entry[1]


class ExactAgenticCommerceScheme:
    """``exact`` server scheme for AWS Marketplace Agentic Commerce.

    :param signer: Signs quote tokens. Its service URL becomes the quote's ``iss``.
    :param dpop_nonce_store: Optional store of seen DPoP proof ids, to reject
        replayed proofs. An id is checked and recorded only after the facilitator
        has accepted the payment token.
    :param dpop_max_age_seconds: Maximum age of a DPoP proof.
    """

    scheme = SCHEME_EXACT
    caip_family = AGENTIC_COMMERCE_CAIP_FAMILY
    default_asset_transfer_method = ASSET_TRANSFER_METHOD
    # Verify before the handler runs; settlement after it is a no-op because the
    # service captures the payment when it issues the payment token.
    payment_flows = MappingProxyType(
        {ASSET_TRANSFER_METHOD: {"supported": ("authorization",), "default": "authorization"}}
    )
    # The quote token is signed fresh for every 402, so x402 core ignores it when
    # matching a buyer's ``accepted`` requirements against the route's. The
    # facilitator checks the quote instead.
    dynamic_extra_fields = DYNAMIC_EXTRA_FIELDS

    def __init__(
        self,
        *,
        signer: QuoteSigner,
        dpop_nonce_store: DPoPNonceStore | None = None,
        dpop_max_age_seconds: int = _DEFAULT_DPOP_MAX_AGE_SECONDS,
    ) -> None:
        self._signer = signer
        self._dpop_nonce_store = dpop_nonce_store
        self._dpop_max_age_seconds = dpop_max_age_seconds
        self._pending_proofs = _PendingProofs()

    @property
    def signer(self) -> QuoteSigner:
        """The quote token signer."""
        return self._signer

    def parse_price(self, price: Price, network: str) -> AssetAmount:
        """Convert a route price into a fiat amount and ISO 4217 asset.

        Amounts are decimal strings (``"0.50"``), not atomic units.

        :param price: ``"$1.50"``, ``"1.50 USD"``, ``1.50``, or an ``AssetAmount``.
        :param network: Target network (pricing does not depend on it).
        :raises ValidationError: if the price cannot be parsed, or its amount has
            more than 8 decimal places.
        """
        # An object price must be a decimal amount with at most 8 decimal places,
        # as for a string price, and an ISO 4217 asset.
        if isinstance(price, AssetAmount):
            _check_asset_amount(price.amount, price.asset)
            return price
        if isinstance(price, dict):
            amount, asset = _check_asset_amount(price.get("amount"), price.get("asset"))
            try:
                return AssetAmount.model_validate(price)
            except pydantic.ValidationError:
                # Pydantic's message would show the rest of the price, such as ``extra``.
                shown = repr({"amount": amount, "asset": asset})
                raise ValidationError(f"Invalid price: {shown}") from None
        if isinstance(price, bool):
            raise ValidationError(f"Invalid price: {price!r}")
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
        if -value.as_tuple().exponent > _MAX_PRICE_DECIMAL_PLACES:  # type: ignore[operator]
            raise ValidationError(
                f"Price may have at most {_MAX_PRICE_DECIMAL_PLACES} decimal places: {price!r}"
            )
        if isinstance(price, (int, float)):
            # Plain decimal notation, never exponent form ("1E-7") or "-0.0".
            amount = format(value.copy_abs(), "f")
        asset = f"iso4217:{currency}" if currency != "USD" else DEFAULT_ASSET
        return AssetAmount(amount=amount, asset=asset, extra={})

    def enhance_payment_requirements(
        self,
        requirements: PaymentRequirements,
        supported_kind: SupportedKind | None = None,
        extensions: list[str] | None = None,
    ) -> PaymentRequirements:
        """Sign a quote token for the requirements and embed it in ``extra.quoteToken``.

        :raises ValidationError: if the amount or asset is not one ``parse_price``
            returns, the signer's service URL or ``payTo`` is empty, or
            ``extra.settlement.product_id`` disagrees with ``payTo``.
        """
        base: dict[str, Any] = requirements.model_dump(by_alias=True, exclude_none=True)
        return PaymentRequirements.model_validate(enhance_payment_requirements(base, self._signer))

    def before_verify(self, context: VerifyContext) -> AbortResult | None:
        """Check the DPoP proof of a DPoP-bound payment token.

        A payment token bound to a key (``cnf.jkt``) is accepted only with a
        ``DPoP`` header proving possession of that key, for this request's method
        and URL, over this payment token. The token's signature is verified
        afterwards by the facilitator, so a token whose binding was altered fails
        there. The token is unverified here, so the nonce store is not touched
        until ``after_verify``.

        With a nonce store, the transport context must support weak references
        (x402's does), or the payment is refused with ``dpop_invalid``.
        """
        # Drop what an earlier request with the same transport context left.
        self._pending_proofs.pop(context.transport_context)
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
            claims = verify_dpop_proof(
                proof,
                {
                    "htm": adapter.get_method().upper(),
                    "htu": adapter.get_url().split("?", 1)[0].split("#", 1)[0],
                    "access_token": payment_token,
                    "max_age": self._dpop_max_age_seconds,
                },
            )
        except DPoPError:
            return AbortResult(reason="dpop_invalid")
        if self._dpop_nonce_store is not None:
            # The id is checked and recorded in after_verify, once the facilitator
            # has accepted the token: a forged token never reaches the store.
            pending = _PendingProof(
                jti=claims["jti"],
                expires_at=_replay_expires_at(int(claims["iat"]), self._dpop_max_age_seconds),
            )
            try:
                self._pending_proofs.set(context.transport_context, pending)
            except TypeError:
                return AbortResult(reason="dpop_invalid")
        return None

    def after_verify(self, context: VerifyResultContext) -> AbortResult | None:
        """Reject a replayed DPoP proof of a payment the facilitator accepted, and record its id.

        ``has`` and ``add`` are called once each, so a store whose ``has`` records
        the id (an atomic check-and-set) works. A store error refuses the payment
        and is logged as a warning.
        """
        pending = self._pending_proofs.pop(context.transport_context)
        if pending is None or not context.result.is_valid:
            return None
        # A proof that is stale, before or during the store lookup, is refused: the
        # store may already have forgotten an earlier use of it.
        if int(time.time()) >= pending.expires_at:
            return AbortResult(reason="dpop_invalid")
        store = cast(DPoPNonceStore, self._dpop_nonce_store)
        try:
            if store.has(pending.jti) or int(time.time()) >= pending.expires_at:
                return AbortResult(reason="dpop_invalid")
            store.add(pending.jti, pending.expires_at)
        except Exception as exc:  # noqa: BLE001 - x402 core does not catch hook errors
            # The type only: the message of a store error may name the proof id.
            logger.warning("DPoP nonce store failed (%s); payment refused", type(exc).__name__)
            return AbortResult(reason="dpop_invalid")
        return None


__all__ = ["ExactAgenticCommerceScheme"]
