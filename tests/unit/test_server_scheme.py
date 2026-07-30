# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for fiat_extension_x402.server_scheme module.

The scheme is a thin adapter over ``enhance_payment_requirements``; what matters
here is the x402 contract — price normalisation, the sync-over-async signer
bridge, and that the signed quote lands in ``extra``.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from x402.schemas import AssetAmount, PaymentRequirements

from fiat_extension_x402.constants import (
    AGENT_PAY_CAIP_FAMILY,
    AGENT_PAY_SCHEME,
    AGENT_PAY_SENTINEL_PAY_TO,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.server_scheme import AgentPayServerScheme


class FakeSigner:
    """Async signer recording what it was asked to sign."""

    def __init__(self, service_url: str = "https://seller.example.com") -> None:
        self._service_url = service_url
        self.signed: list[dict[str, Any]] = []

    async def sign_quote(self, payload: dict[str, Any]) -> str:
        self.signed.append(payload)
        return "eyJ.signed.quote"

    def get_public_key(self) -> object:
        return {}

    def get_service_url(self) -> str:
        return self._service_url


def _requirements(**overrides: Any) -> PaymentRequirements:
    base: dict[str, Any] = {
        "scheme": AGENT_PAY_SCHEME,
        "network": "aws:base",
        "asset": "iso4217:USD",
        "amount": "0.15",
        "payTo": "seller-1",
        "maxTimeoutSeconds": 300,
        "extra": {},
    }
    base.update(overrides)
    return PaymentRequirements.model_validate(base)


class TestSchemeIdentity:
    def test_scheme_and_family(self) -> None:
        scheme = AgentPayServerScheme(signer=FakeSigner())
        assert scheme.scheme == AGENT_PAY_SCHEME
        assert scheme.caip_family == AGENT_PAY_CAIP_FAMILY

    def test_exposes_signer(self) -> None:
        signer = FakeSigner()
        assert AgentPayServerScheme(signer=signer).signer is signer


class TestParsePrice:
    @pytest.mark.parametrize(
        ("price", "amount", "asset"),
        [
            ("0.50", "0.5", "iso4217:USD"),
            ("$1.50", "1.5", "iso4217:USD"),
            ("2.00 EUR", "2.0", "iso4217:EUR"),
            (0.15, "0.15", "iso4217:USD"),
            (3, "3.0", "iso4217:USD"),
        ],
    )
    def test_normalises_money(self, price: Any, amount: str, asset: str) -> None:
        result = AgentPayServerScheme(signer=FakeSigner()).parse_price(price, "aws:base")
        assert (result.amount, result.asset) == (amount, asset)

    def test_passes_through_asset_amount(self) -> None:
        given = AssetAmount(amount="0.99", asset="iso4217:GBP")
        result = AgentPayServerScheme(signer=FakeSigner()).parse_price(given, "aws:base")
        assert result is given

    def test_accepts_asset_amount_dict(self) -> None:
        result = AgentPayServerScheme(signer=FakeSigner()).parse_price(
            {"amount": "0.42", "asset": "iso4217:USD"}, "aws:base"
        )
        assert result.amount == "0.42"

    def test_rejects_malformed_money(self) -> None:
        with pytest.raises(ValidationError, match="Invalid money format"):
            AgentPayServerScheme(signer=FakeSigner()).parse_price("free", "aws:base")


class TestEnhancePaymentRequirements:
    def test_embeds_signed_quote_token(self) -> None:
        signer = FakeSigner()
        enhanced = AgentPayServerScheme(signer=signer).enhance_payment_requirements(_requirements())
        assert enhanced.extra["quoteToken"] == "eyJ.signed.quote"
        assert len(signer.signed) == 1

    def test_replaces_pay_to_with_sentinel(self) -> None:
        """The signed quote is authoritative for the recipient."""
        enhanced = AgentPayServerScheme(signer=FakeSigner()).enhance_payment_requirements(
            _requirements(payTo="seller-1")
        )
        assert enhanced.pay_to == AGENT_PAY_SENTINEL_PAY_TO

    def test_quote_claims_carry_issuer_and_price(self) -> None:
        signer = FakeSigner("https://seller.example.com")
        AgentPayServerScheme(signer=signer).enhance_payment_requirements(
            _requirements(amount="2.50", asset="iso4217:EUR")
        )
        claims = signer.signed[0]
        assert claims["iss"] == "https://seller.example.com"
        assert claims["price"] == {"amount": "2.50", "currency": "EUR"}
        assert claims["payTo"] == "seller-1"

    def test_preserves_caller_extra(self) -> None:
        enhanced = AgentPayServerScheme(signer=FakeSigner()).enhance_payment_requirements(
            _requirements(extra={"settlement": {"product_id": "prod-1"}})
        )
        assert enhanced.extra["settlement"] == {"product_id": "prod-1"}
        assert enhanced.extra["quoteToken"]

    def test_rejects_empty_issuer(self) -> None:
        with pytest.raises(ValidationError, match="issuer"):
            AgentPayServerScheme(signer=FakeSigner("")).enhance_payment_requirements(
                _requirements()
            )

    def test_accepts_optional_x402_arguments(self) -> None:
        """supported_kind/extensions are accepted for contract compatibility."""
        enhanced = AgentPayServerScheme(signer=FakeSigner()).enhance_payment_requirements(
            _requirements(), None, ["some-extension"]
        )
        assert enhanced.extra["quoteToken"]


class TestSignerBridge:
    def test_works_without_a_running_event_loop(self) -> None:
        enhanced = AgentPayServerScheme(signer=FakeSigner()).enhance_payment_requirements(
            _requirements()
        )
        assert enhanced.extra["quoteToken"]

    def test_works_inside_a_running_event_loop(self) -> None:
        """x402 core calls the scheme synchronously even from async servers."""
        scheme = AgentPayServerScheme(signer=FakeSigner())

        async def drive() -> PaymentRequirements:
            return scheme.enhance_payment_requirements(_requirements())

        enhanced = asyncio.run(drive())
        assert enhanced.extra["quoteToken"]

    def test_signer_offloading_to_a_thread_still_works(self) -> None:
        """Mirrors the KMS signer, which wraps a blocking call in to_thread."""

        class ThreadOffloadSigner(FakeSigner):
            async def sign_quote(self, payload: dict[str, Any]) -> str:
                return await asyncio.to_thread(lambda: "eyJ.kms.quote")

        scheme = AgentPayServerScheme(signer=ThreadOffloadSigner())

        async def drive() -> PaymentRequirements:
            return scheme.enhance_payment_requirements(_requirements())

        assert asyncio.run(drive()).extra["quoteToken"] == "eyJ.kms.quote"
