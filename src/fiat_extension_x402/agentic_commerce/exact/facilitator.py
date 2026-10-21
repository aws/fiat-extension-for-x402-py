# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Facilitator side of the ``exact`` scheme on AWS Marketplace Agentic Commerce networks.

Register it on an x402 facilitator. The facilitator can run in the seller's own
process (no network hop) or as a separate service::

    from x402 import x402Facilitator
    facilitator = x402Facilitator()
    facilitator.register(["aws:base"], ExactAgenticCommerceFacilitatorScheme(verifier=verifier))
"""

from __future__ import annotations

from typing import Any

import jwt
from x402.schemas import (
    PaymentPayload,
    PaymentPayloadV1,
    PaymentRequirements,
    PaymentRequirementsV1,
    SettleResponse,
    VerifyResponse,
)

from fiat_extension_x402.agentic_commerce.verifier import AgenticCommerceVerifier
from fiat_extension_x402.constants import AGENTIC_COMMERCE_CAIP_FAMILY, SCHEME_EXACT

_AnyPayload = PaymentPayload | PaymentPayloadV1
_AnyRequirements = PaymentRequirements | PaymentRequirementsV1


class ExactAgenticCommerceScheme:
    """``exact`` facilitator scheme for AWS Marketplace Agentic Commerce.

    :param verifier: Verifies payment tokens. Configure it with the seller's key.
    """

    scheme = SCHEME_EXACT
    caip_family = AGENTIC_COMMERCE_CAIP_FAMILY

    def __init__(self, *, verifier: AgenticCommerceVerifier) -> None:
        self._verifier = verifier

    @property
    def verifier(self) -> AgenticCommerceVerifier:
        """The payment token verifier."""
        return self._verifier

    def get_extra(self, network: str) -> dict[str, Any] | None:
        """No scheme-specific data is advertised."""
        return None

    def get_signers(self, network: str) -> list[str]:
        """No on-chain signers: the service authorizes payments."""
        return []

    def verify(
        self,
        payload: _AnyPayload,
        requirements: _AnyRequirements,
        context: Any = None,
    ) -> VerifyResponse:
        """Verify the payment token in ``payload.payload["paymentToken"]``.

        Never raises for an invalid payment: failures are returned as a
        ``VerifyResponse`` with ``is_valid=False``, per the x402 facilitator contract.
        """
        payment_token = (payload.payload or {}).get("paymentToken")
        if not isinstance(payment_token, str) or not payment_token:
            return VerifyResponse(
                is_valid=False,
                invalid_reason="invalid_payment",
                invalid_message="Missing paymentToken in payment payload",
            )
        result = self._verifier.verify(
            payment_token,
            _wire_requirements(payload, requirements),
            route_quote_token=_route_quote_token(requirements),
        )
        return VerifyResponse(
            is_valid=result.is_valid,
            invalid_reason=result.invalid_reason,
            invalid_message=result.invalid_message,
            payer=result.payer,
        )

    def settle(
        self,
        payload: _AnyPayload,
        requirements: _AnyRequirements,
        context: Any = None,
    ) -> SettleResponse:
        """Settle a verified payment: a no-op.

        The service captures the payment when it issues the payment token, so
        there is nothing to settle. The payment id is returned as the transaction.

        Nothing records the payment here, so the same payment settles again
        until it expires. A seller accepts each payment once by recording its
        ``transaction`` (the payment id); see ``docs/security.md``.
        """
        payment_token = (payload.payload or {}).get("paymentToken") or ""
        try:
            claims = jwt.decode(str(payment_token), options={"verify_signature": False})
        except jwt.PyJWTError:
            claims = {}
        return SettleResponse(
            success=True,
            transaction=str(claims.get("payment_id") or ""),
            network=str(requirements.network),
            payer=claims.get("sub"),
        )


def _wire_requirements(payload: _AnyPayload, requirements: _AnyRequirements) -> dict[str, Any]:
    """The terms to verify the payment against, with wire field names.

    Price and asset come from ``requirements``: the server's own requirements for
    the route. The quote comes from the buyer's ``accepted`` requirements: x402
    core matches those against the server's while ignoring the quote token
    (signed afresh for every 402), so the server's copy holds a newer quote than
    the one the buyer paid for. The quote is signed by the seller, which the
    verifier checks. v1 payloads have no ``accepted`` and v1 requirements name
    the amount ``maxAmountRequired``.
    """
    amount = getattr(requirements, "amount", None)
    if amount is None:
        amount = getattr(requirements, "max_amount_required", None)
    accepted = getattr(payload, "accepted", None)
    quote_source = accepted if accepted is not None else requirements
    quote_token = (getattr(quote_source, "extra", None) or {}).get("quoteToken")
    return {"amount": amount, "asset": requirements.asset, "extra": {"quoteToken": quote_token}}


def _route_quote_token(requirements: _AnyRequirements) -> str | None:
    """The quote the server signed for the route in these requirements.

    The buyer's quote must be for the same route; see
    :meth:`AgenticCommerceVerifier.verify`.
    """
    quote_token = (getattr(requirements, "extra", None) or {}).get("quoteToken")
    return quote_token if isinstance(quote_token, str) and quote_token else None


__all__ = ["ExactAgenticCommerceScheme"]
