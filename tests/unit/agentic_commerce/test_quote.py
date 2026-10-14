# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for quote token creation."""

from __future__ import annotations

import time
import uuid
from typing import Any

import jwt
import pytest

from fiat_extension_x402.agentic_commerce.quote import enhance_payment_requirements
from fiat_extension_x402.constants import (
    DEFAULT_QUOTE_VALIDITY_SECONDS,
    QUOTE_TOKEN_AUDIENCE,
    SENTINEL_PAY_TO,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.signers import LocalQuoteSigner
from tests.support import SELLER_URL, seller_signer


def _requirements(**overrides: Any) -> dict[str, Any]:
    requirements: dict[str, Any] = {
        "scheme": "exact",
        "network": "aws:base",
        "asset": "iso4217:USD",
        "amount": "0.10",
        "payTo": "seller-1",
    }
    requirements.update(overrides)
    return requirements


def _quote(signer: LocalQuoteSigner, enhanced: dict[str, Any]) -> dict[str, Any]:
    claims: dict[str, Any] = jwt.decode(
        enhanced["extra"]["quoteToken"],
        jwt.PyJWK.from_dict(signer.public_jwk).key,
        algorithms=["ES256"],
        audience=QUOTE_TOKEN_AUDIENCE,
    )
    return claims


class _RecordingSigner:
    """A signer that records the claims it is asked to sign."""

    def __init__(self, service_url: str = SELLER_URL) -> None:
        self.service_url = service_url
        self.signed: list[dict[str, Any]] = []

    def sign_quote(self, payload: dict[str, Any]) -> str:
        self.signed.append(payload)
        return "signed-quote"

    def get_service_url(self) -> str:
        return self.service_url


class TestQuoteClaims:
    def test_required_claims(self) -> None:
        signer = seller_signer()
        before = int(time.time())
        claims = _quote(signer, enhance_payment_requirements(_requirements(), signer))
        after = int(time.time())

        assert claims["iss"] == SELLER_URL
        assert claims["aud"] == QUOTE_TOKEN_AUDIENCE
        assert before <= claims["iat"] <= after
        assert claims["exp"] - claims["iat"] == DEFAULT_QUOTE_VALIDITY_SECONDS
        assert uuid.UUID(claims["jti"])
        assert claims["price"] == {"amount": "0.10", "currency": "USD"}
        assert claims["payTo"] == "seller-1"
        assert claims["reference"] == "RESOURCE"

    def test_quote_is_signed_with_seller_kid(self) -> None:
        signer = seller_signer()
        enhanced = enhance_payment_requirements(_requirements(), signer)
        assert jwt.get_unverified_header(enhanced["extra"]["quoteToken"])["kid"] == "seller-key"

    def test_each_quote_has_a_fresh_jti(self) -> None:
        signer = _RecordingSigner()
        enhance_payment_requirements(_requirements(), signer)
        enhance_payment_requirements(_requirements(), signer)
        assert signer.signed[0]["jti"] != signer.signed[1]["jti"]

    def test_non_usd_currency(self) -> None:
        signer = _RecordingSigner()
        enhance_payment_requirements(_requirements(asset="iso4217:EUR", amount="2"), signer)
        assert signer.signed[0]["price"] == {"amount": "2", "currency": "EUR"}

    def test_amount_kept_verbatim(self) -> None:
        signer = _RecordingSigner()
        enhance_payment_requirements(_requirements(amount="02.50"), signer)
        assert signer.signed[0]["price"] == {"amount": "02.50", "currency": "USD"}

    # The same rules as parse_price, for a caller that skips it.
    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            (
                {"amount": "0.123456789"},
                (
                    "Price may have at most 8 decimal places: "
                    "{'amount': '0.123456789', 'asset': 'iso4217:USD'}"
                ),
            ),
            ({"amount": "1e5"}, "Invalid price: {'amount': '1e5', 'asset': 'iso4217:USD'}"),
            ({"amount": 5}, "Invalid price: {'amount': 5, 'asset': 'iso4217:USD'}"),
            ({"asset": "USD"}, "Invalid price: {'amount': '0.10', 'asset': 'USD'}"),
            (
                {"asset": "iso4217:iso4217:GBP"},
                "Invalid price: {'amount': '0.10', 'asset': 'iso4217:iso4217:GBP'}",
            ),
            ({"asset": None}, "Invalid price: {'amount': '0.10', 'asset': None}"),
            ({"amount": None}, "Invalid price: {'amount': None, 'asset': 'iso4217:USD'}"),
        ],
    )
    def test_malformed_price_signs_no_quote(self, overrides: dict[str, Any], message: str) -> None:
        signer = _RecordingSigner()
        requirements = _requirements(**overrides)
        for name, value in overrides.items():
            if value is None:
                del requirements[name]
        with pytest.raises(ValidationError) as raised:
            enhance_payment_requirements(requirements, signer)
        assert str(raised.value) == message
        assert signer.signed == []

    def test_reference_from_extra(self) -> None:
        signer = _RecordingSigner()
        enhance_payment_requirements(_requirements(extra={"reference": "ORDER-7"}), signer)
        assert signer.signed[0]["reference"] == "ORDER-7"

    def test_optional_claims_copied_from_extra(self) -> None:
        signer = _RecordingSigner()
        extra = {
            "description": "Weather",
            "dimensions": [{"name": "calls", "quantity": 1}],
            "settlement": {"mode": "immediate"},
            "support": "https://seller.example.com/support",
            "terms": "https://seller.example.com/terms",
            "unrelated": "not copied",
        }
        enhance_payment_requirements(_requirements(extra=extra), signer)
        claims = signer.signed[0]
        for name in ("description", "dimensions", "support", "terms"):
            assert claims[name] == extra[name]
        assert claims["settlement"] == {"mode": "immediate", "product_id": "seller-1"}
        assert "unrelated" not in claims

    def test_optional_claims_absent_or_none_are_omitted(self) -> None:
        signer = _RecordingSigner()
        enhance_payment_requirements(_requirements(extra={"description": None}), signer)
        claims = signer.signed[0]
        for name in ("description", "dimensions", "support", "terms"):
            assert name not in claims


class TestProductId:
    def test_settlement_product_id_is_pay_to(self) -> None:
        signer = _RecordingSigner()
        enhance_payment_requirements(_requirements(payTo="prod-abc123"), signer)
        assert signer.signed[0]["settlement"] == {"product_id": "prod-abc123"}

    def test_matching_explicit_product_id_is_accepted(self) -> None:
        signer = _RecordingSigner()
        extra = {"settlement": {"product_id": "prod-abc123"}}
        enhance_payment_requirements(_requirements(payTo="prod-abc123", extra=extra), signer)
        assert signer.signed[0]["settlement"] == {"product_id": "prod-abc123"}

    def test_conflicting_product_id_raises(self) -> None:
        extra = {"settlement": {"product_id": "prod-other"}}
        with pytest.raises(ValidationError, match="must match payTo"):
            enhance_payment_requirements(
                _requirements(payTo="prod-abc123", extra=extra), _RecordingSigner()
            )

    @pytest.mark.parametrize("pay_to", ["", "   ", None])
    def test_missing_pay_to_raises(self, pay_to: Any) -> None:
        with pytest.raises(ValidationError, match="product ID"):
            enhance_payment_requirements(_requirements(payTo=pay_to), _RecordingSigner())

    def test_route_extra_is_not_modified(self) -> None:
        extra: dict[str, Any] = {"settlement": {"mode": "immediate"}}
        enhanced = enhance_payment_requirements(_requirements(extra=extra), _RecordingSigner())
        assert extra == {"settlement": {"mode": "immediate"}}
        assert enhanced["extra"]["settlement"] == {"mode": "immediate"}


class TestEnhancedRequirements:
    def test_pay_to_is_sentinel(self) -> None:
        enhanced = enhance_payment_requirements(_requirements(), _RecordingSigner())
        assert enhanced["payTo"] == SENTINEL_PAY_TO

    def test_quote_carries_original_pay_to(self) -> None:
        signer = _RecordingSigner()
        enhance_payment_requirements(_requirements(payTo="seller-42"), signer)
        assert signer.signed[0]["payTo"] == "seller-42"

    def test_max_timeout_defaults_to_quote_validity(self) -> None:
        enhanced = enhance_payment_requirements(_requirements(), _RecordingSigner())
        assert enhanced["maxTimeoutSeconds"] == DEFAULT_QUOTE_VALIDITY_SECONDS

    def test_max_timeout_override_sets_quote_validity(self) -> None:
        signer = _RecordingSigner()
        enhanced = enhance_payment_requirements(_requirements(maxTimeoutSeconds=42), signer)
        assert enhanced["maxTimeoutSeconds"] == 42
        assert signer.signed[0]["exp"] - signer.signed[0]["iat"] == 42

    def test_zero_max_timeout_falls_back_to_default(self) -> None:
        enhanced = enhance_payment_requirements(
            _requirements(maxTimeoutSeconds=0), _RecordingSigner()
        )
        assert enhanced["maxTimeoutSeconds"] == DEFAULT_QUOTE_VALIDITY_SECONDS

    def test_quote_token_embedded_in_extra(self) -> None:
        enhanced = enhance_payment_requirements(_requirements(), _RecordingSigner())
        assert enhanced["extra"]["quoteToken"] == "signed-quote"

    def test_original_extra_preserved_and_not_mutated(self) -> None:
        extra = {"reference": "ORDER-7", "custom": {"a": 1}}
        requirements = _requirements(extra=extra)
        enhanced = enhance_payment_requirements(requirements, _RecordingSigner())
        assert enhanced["extra"] == {
            "reference": "ORDER-7",
            "custom": {"a": 1},
            "quoteToken": "signed-quote",
        }
        assert "quoteToken" not in extra
        assert requirements["payTo"] == "seller-1"

    def test_other_fields_preserved(self) -> None:
        enhanced = enhance_payment_requirements(_requirements(), _RecordingSigner())
        for name in ("scheme", "network", "asset", "amount"):
            assert enhanced[name] == _requirements()[name]


class TestIssuerValidation:
    @pytest.mark.parametrize("service_url", ["", "   "])
    def test_empty_issuer_raises(self, service_url: str) -> None:
        signer = _RecordingSigner(service_url)
        with pytest.raises(ValidationError, match="issuer"):
            enhance_payment_requirements(_requirements(), signer)
        assert signer.signed == []
