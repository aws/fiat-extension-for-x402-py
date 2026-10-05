# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the facilitator side of the ``exact`` scheme."""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import httpx
import jwt
import pytest
import respx
from x402.schemas import PaymentPayload, PaymentRequirements

from fiat_extension_x402.agentic_commerce import (
    AgenticCommerceVerifier,
    StaticSellerKeyResolver,
)
from fiat_extension_x402.agentic_commerce.exact import (
    ExactAgenticCommerceFacilitatorScheme,
    ExactAgenticCommerceServerScheme,
)
from fiat_extension_x402.signers import LocalQuoteSigner
from tests.support import SERVICE_JWKS_BASE_URL, FakePaymentService, seller_signer


@pytest.fixture
def service() -> Iterator[FakePaymentService]:
    service = FakePaymentService()
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{SERVICE_JWKS_BASE_URL}/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=service.jwks)
        )
        yield service


@pytest.fixture
def signer() -> LocalQuoteSigner:
    return seller_signer()


@pytest.fixture
def scheme(signer: LocalQuoteSigner) -> ExactAgenticCommerceFacilitatorScheme:
    verifier = AgenticCommerceVerifier(
        seller_key_resolver=StaticSellerKeyResolver(signer.public_jwk),
        payment_token_jwks_url=SERVICE_JWKS_BASE_URL,
    )
    return ExactAgenticCommerceFacilitatorScheme(verifier=verifier)


def _offer(signer: LocalQuoteSigner, amount: str = "0.10") -> PaymentRequirements:
    """Requirements as the seller sends them in a 402: with a fresh quote."""
    base = PaymentRequirements(
        scheme="exact",
        network="aws:base",
        asset="iso4217:USD",
        amount=amount,
        pay_to="seller-1",
        max_timeout_seconds=300,
    )
    return ExactAgenticCommerceServerScheme(signer=signer).enhance_payment_requirements(base)


def _quote(requirements: Any) -> str:
    quote: str = requirements.extra["quoteToken"]
    return quote


def _payload(accepted: PaymentRequirements, payment: dict[str, Any]) -> PaymentPayload:
    return PaymentPayload(payload=payment, accepted=accepted)


class TestAccessors:
    def test_class_attributes(self) -> None:
        assert ExactAgenticCommerceFacilitatorScheme.scheme == "exact"
        assert ExactAgenticCommerceFacilitatorScheme.caip_family == "aws:*"

    def test_verifier_property(self, signer: LocalQuoteSigner) -> None:
        verifier = AgenticCommerceVerifier(
            seller_key_resolver=StaticSellerKeyResolver(signer.public_jwk)
        )
        assert ExactAgenticCommerceFacilitatorScheme(verifier=verifier).verifier is verifier

    def test_get_extra(self, scheme: ExactAgenticCommerceFacilitatorScheme) -> None:
        assert scheme.get_extra("aws:base") is None

    def test_get_signers(self, scheme: ExactAgenticCommerceFacilitatorScheme) -> None:
        assert scheme.get_signers("aws:base") == []


class TestVerify:
    def test_valid(
        self,
        service: FakePaymentService,
        signer: LocalQuoteSigner,
        scheme: ExactAgenticCommerceFacilitatorScheme,
    ) -> None:
        offer = _offer(signer)
        token = service.issue(_quote(offer), buyer="210987654321")
        result = scheme.verify(_payload(offer, {"paymentToken": token}), offer)
        assert result.is_valid is True
        assert result.payer == "210987654321"
        assert result.invalid_reason is None

    @pytest.mark.parametrize("payment", [{}, {"paymentToken": ""}, {"paymentToken": 42}])
    def test_missing_payment_token(
        self,
        signer: LocalQuoteSigner,
        scheme: ExactAgenticCommerceFacilitatorScheme,
        payment: dict[str, Any],
    ) -> None:
        offer = _offer(signer)
        result = scheme.verify(_payload(offer, payment), offer)
        assert result.is_valid is False
        assert result.invalid_reason == "invalid_payment"
        assert result.invalid_message == "Missing paymentToken in payment payload"

    def test_quote_comes_from_accepted_requirements(
        self,
        service: FakePaymentService,
        signer: LocalQuoteSigner,
        scheme: ExactAgenticCommerceFacilitatorScheme,
    ) -> None:
        # The buyer paid for the quote it accepted; the server's own copy of
        # the requirements holds a newer quote signed for a later 402.
        accepted = _offer(signer)
        server_requirements = _offer(signer)
        assert _quote(accepted) != _quote(server_requirements)
        token = service.issue(_quote(accepted))

        result = scheme.verify(_payload(accepted, {"paymentToken": token}), server_requirements)
        assert result.is_valid is True

    def test_payment_for_server_quote_but_not_accepted_quote_is_rejected(
        self,
        service: FakePaymentService,
        signer: LocalQuoteSigner,
        scheme: ExactAgenticCommerceFacilitatorScheme,
    ) -> None:
        accepted = _offer(signer)
        server_requirements = _offer(signer)
        token = service.issue(_quote(server_requirements))

        result = scheme.verify(_payload(accepted, {"paymentToken": token}), server_requirements)
        assert result.is_valid is False
        assert result.invalid_reason == "invalid_quote"

    def test_price_comes_from_server_requirements(
        self,
        service: FakePaymentService,
        signer: LocalQuoteSigner,
        scheme: ExactAgenticCommerceFacilitatorScheme,
    ) -> None:
        # A buyer cannot lower the price by editing its ``accepted`` copy.
        accepted = _offer(signer, amount="0.01")
        server_requirements = _offer(signer, amount="0.10")
        token = service.issue(_quote(accepted))

        result = scheme.verify(_payload(accepted, {"paymentToken": token}), server_requirements)
        assert result.is_valid is False
        assert result.invalid_reason == "invalid_payment"
        assert result.invalid_message == "Amount or currency mismatch"

    def test_v1_requirements_without_accepted(
        self,
        service: FakePaymentService,
        signer: LocalQuoteSigner,
        scheme: ExactAgenticCommerceFacilitatorScheme,
    ) -> None:
        offer = _offer(signer)
        v1_requirements = SimpleNamespace(
            max_amount_required="0.10",
            asset="iso4217:USD",
            network="aws:base",
            extra={"quoteToken": _quote(offer)},
        )
        v1_payload = SimpleNamespace(payload={"paymentToken": service.issue(_quote(offer))})

        result = scheme.verify(v1_payload, v1_requirements)  # type: ignore[arg-type]
        assert result.is_valid is True

    def test_v1_requirements_without_extra(
        self,
        service: FakePaymentService,
        scheme: ExactAgenticCommerceFacilitatorScheme,
    ) -> None:
        v1_requirements = SimpleNamespace(
            max_amount_required="0.10", asset="iso4217:USD", network="aws:base", extra=None
        )
        v1_payload = SimpleNamespace(payload={"paymentToken": "token"})

        result = scheme.verify(v1_payload, v1_requirements)  # type: ignore[arg-type]
        assert result.is_valid is False
        assert result.invalid_reason == "invalid_quote"

    def test_payload_none(self, scheme: ExactAgenticCommerceFacilitatorScheme) -> None:
        result = scheme.verify(
            SimpleNamespace(payload=None),  # type: ignore[arg-type]
            SimpleNamespace(amount="0.10", asset="iso4217:USD", extra={}),  # type: ignore[arg-type]
        )
        assert result.invalid_reason == "invalid_payment"


class TestSettle:
    def test_returns_payment_id(
        self,
        service: FakePaymentService,
        signer: LocalQuoteSigner,
        scheme: ExactAgenticCommerceFacilitatorScheme,
    ) -> None:
        offer = _offer(signer)
        token = service.issue(_quote(offer), buyer="210987654321")
        payment_id = jwt.decode(token, options={"verify_signature": False})["payment_id"]

        result = scheme.settle(_payload(offer, {"paymentToken": token}), offer)

        assert result.success is True
        assert result.transaction == payment_id
        assert result.payer == "210987654321"
        assert result.network == "aws:base"

    def test_malformed_token(
        self, signer: LocalQuoteSigner, scheme: ExactAgenticCommerceFacilitatorScheme
    ) -> None:
        offer = _offer(signer)
        result = scheme.settle(_payload(offer, {"paymentToken": "not-a-jwt"}), offer)
        assert result.success is True
        assert result.transaction == ""
        assert result.payer is None
        assert result.network == "aws:base"

    def test_missing_token(
        self, signer: LocalQuoteSigner, scheme: ExactAgenticCommerceFacilitatorScheme
    ) -> None:
        offer = _offer(signer)
        result = scheme.settle(_payload(offer, {}), offer)
        assert result.success is True
        assert result.transaction == ""

    def test_payload_none(self, scheme: ExactAgenticCommerceFacilitatorScheme) -> None:
        result = scheme.settle(
            SimpleNamespace(payload=None),  # type: ignore[arg-type]
            SimpleNamespace(network="aws:base"),  # type: ignore[arg-type]
        )
        assert result.transaction == ""
