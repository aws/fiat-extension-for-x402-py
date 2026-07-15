# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the server scheme (enhance_payment_requirements)."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from fiat_extension_x402.constants import (
    AGENT_PAY_AUDIENCE,
    AGENT_PAY_SENTINEL_PAY_TO,
    DEFAULT_QUOTE_VALIDITY_SECONDS,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.server.scheme import enhance_payment_requirements


class _FakeSigner:
    """Fake signer that captures payloads for inspection."""

    def __init__(self, service_url: str = "https://api.example.com") -> None:
        self._service_url = service_url
        self.last_payload: dict[str, Any] | None = None

    async def sign_quote(self, payload: dict[str, Any]) -> str:
        self.last_payload = payload
        return "fake.jwt.token"

    def get_public_key(self) -> object:
        return {}

    def get_service_url(self) -> str:
        return self._service_url


class TestEnhancePaymentRequirements:
    """Tests for enhance_payment_requirements."""

    @pytest.mark.asyncio
    async def test_basic_enhancement(self) -> None:
        signer = _FakeSigner()
        base_requirements: dict[str, Any] = {
            "amount": "0.15",
            "asset": "iso4217:USD",
            "payTo": "seller-123",
            "maxTimeoutSeconds": 300,
            "extra": {"reference": "my-product"},
        }

        result = await enhance_payment_requirements(base_requirements, signer)

        # payTo replaced with sentinel.
        assert result["payTo"] == AGENT_PAY_SENTINEL_PAY_TO

        # maxTimeoutSeconds preserved from quote payload.
        assert result["maxTimeoutSeconds"] == 300

        # extra contains quoteToken.
        assert result["extra"]["quoteToken"] == "fake.jwt.token"

        # Original extra fields preserved.
        assert result["extra"]["reference"] == "my-product"

    @pytest.mark.asyncio
    async def test_quote_payload_claims(self) -> None:
        signer = _FakeSigner(service_url="https://my-service.io")
        base_requirements: dict[str, Any] = {
            "amount": "10.50",
            "asset": "iso4217:EUR",
            "payTo": "seller-xyz",
            "maxTimeoutSeconds": 600,
            "extra": {
                "reference": "premium-plan",
                "description": "Monthly subscription",
                "dimensions": {"tokens": 5000},
                "settlement": {"method": "INST"},
                "support": {"uri": "https://support.example.com", "method": "human"},
                "terms": [{"description": "ToS", "uri": "https://tos.example.com"}],
            },
        }

        with patch("fiat_extension_x402.server.scheme.time", return_value=1700000000.0):
            with patch(
                "fiat_extension_x402.server.scheme.uuid.uuid4",
                return_value="fixed-uuid-1234",
            ):
                await enhance_payment_requirements(base_requirements, signer)

        payload = signer.last_payload
        assert payload is not None
        assert payload["iss"] == "https://my-service.io"
        assert payload["aud"] == AGENT_PAY_AUDIENCE
        assert payload["iat"] == 1700000000
        assert payload["exp"] == 1700000600
        assert payload["jti"] == "fixed-uuid-1234"
        assert payload["price"] == {"amount": "10.50", "currency": "EUR"}
        assert payload["payTo"] == "seller-xyz"
        assert payload["reference"] == "premium-plan"
        assert payload["description"] == "Monthly subscription"
        assert payload["dimensions"] == {"tokens": 5000}
        assert payload["settlement"] == {"method": "INST"}
        assert payload["support"] == {
            "uri": "https://support.example.com",
            "method": "human",
        }
        assert payload["terms"] == [{"description": "ToS", "uri": "https://tos.example.com"}]

    @pytest.mark.asyncio
    async def test_default_quote_validity_when_no_timeout(self) -> None:
        signer = _FakeSigner()
        base_requirements: dict[str, Any] = {
            "amount": "1.00",
            "asset": "iso4217:USD",
            "payTo": "seller-abc",
            "extra": {},
        }

        with patch("fiat_extension_x402.server.scheme.time", return_value=1700000000.0):
            result = await enhance_payment_requirements(base_requirements, signer)

        assert signer.last_payload is not None
        assert signer.last_payload["exp"] == 1700000000 + DEFAULT_QUOTE_VALIDITY_SECONDS
        assert result["maxTimeoutSeconds"] == DEFAULT_QUOTE_VALIDITY_SECONDS

    @pytest.mark.asyncio
    async def test_default_reference_is_resource(self) -> None:
        signer = _FakeSigner()
        base_requirements: dict[str, Any] = {
            "amount": "5.00",
            "asset": "iso4217:GBP",
            "payTo": "seller-uk",
            "extra": {},
        }

        await enhance_payment_requirements(base_requirements, signer)

        assert signer.last_payload is not None
        assert signer.last_payload["reference"] == "RESOURCE"

    @pytest.mark.asyncio
    async def test_optional_claims_excluded_when_absent(self) -> None:
        signer = _FakeSigner()
        base_requirements: dict[str, Any] = {
            "amount": "2.00",
            "asset": "iso4217:USD",
            "payTo": "seller-no-extras",
            "extra": {},
        }

        await enhance_payment_requirements(base_requirements, signer)

        payload = signer.last_payload
        assert payload is not None
        assert "description" not in payload
        assert "dimensions" not in payload
        assert "settlement" not in payload
        assert "support" not in payload
        assert "terms" not in payload

    @pytest.mark.asyncio
    async def test_no_extra_field_defaults_to_empty(self) -> None:
        signer = _FakeSigner()
        base_requirements: dict[str, Any] = {
            "amount": "0.50",
            "asset": "iso4217:USD",
            "payTo": "seller-minimal",
        }

        result = await enhance_payment_requirements(base_requirements, signer)

        assert "quoteToken" in result["extra"]
        assert signer.last_payload is not None
        assert signer.last_payload["reference"] == "RESOURCE"

    @pytest.mark.asyncio
    async def test_does_not_mutate_original_requirements(self) -> None:
        signer = _FakeSigner()
        original_extra: dict[str, Any] = {"reference": "keep-me"}
        base_requirements: dict[str, Any] = {
            "amount": "1.00",
            "asset": "iso4217:USD",
            "payTo": "seller-immutable",
            "extra": original_extra,
        }

        result = await enhance_payment_requirements(base_requirements, signer)

        # Original dict should not be mutated.
        assert "quoteToken" not in original_extra
        assert result is not base_requirements

    @pytest.mark.asyncio
    async def test_amount_and_asset_stay_real(self) -> None:
        """payTo becomes the sentinel, but amount/asset remain the real values."""
        signer = _FakeSigner()
        base_requirements: dict[str, Any] = {
            "amount": "1.50",
            "asset": "iso4217:USD",
            "payTo": "service-pay",
            "maxTimeoutSeconds": 3600,
            "extra": {},
        }

        result = await enhance_payment_requirements(base_requirements, signer)

        assert result["payTo"] == AGENT_PAY_SENTINEL_PAY_TO
        assert result["amount"] == "1.50"
        assert result["asset"] == "iso4217:USD"

    @pytest.mark.asyncio
    async def test_multiple_price_currencies(self) -> None:
        """The currency is taken from the iso4217 asset for several currencies."""
        signer = _FakeSigner()
        for currency in ("USD", "EUR", "GBP"):
            base_requirements: dict[str, Any] = {
                "amount": "1.50",
                "asset": f"iso4217:{currency}",
                "payTo": "seller",
                "extra": {},
            }
            await enhance_payment_requirements(base_requirements, signer)
            assert signer.last_payload is not None
            assert signer.last_payload["price"]["currency"] == currency

    @pytest.mark.asyncio
    async def test_currency_stripped_from_iso4217_prefix(self) -> None:
        signer = _FakeSigner()
        base_requirements: dict[str, Any] = {
            "amount": "99.99",
            "asset": "iso4217:JPY",
            "payTo": "seller-jp",
            "extra": {},
        }

        await enhance_payment_requirements(base_requirements, signer)

        assert signer.last_payload is not None
        assert signer.last_payload["price"]["currency"] == "JPY"


class TestEmptyIssuerValidation:
    """The issuer (signer service URL) must be non-empty.

    Regression guard: a signer built with an empty service_url produced a quote
    token with ``iss: ""``, which Agent Pay rejects with a 400. Validate before
    signing so no signer type can emit an empty-issuer token.
    """

    @pytest.mark.asyncio
    async def test_empty_issuer_raises_validation_error(self) -> None:
        signer = _FakeSigner(service_url="")
        base_requirements: dict[str, Any] = {
            "amount": "1.00",
            "asset": "iso4217:USD",
            "payTo": "seller",
            "extra": {},
        }

        with pytest.raises(ValidationError, match="issuer"):
            await enhance_payment_requirements(base_requirements, signer)

    @pytest.mark.asyncio
    async def test_whitespace_only_issuer_raises_validation_error(self) -> None:
        signer = _FakeSigner(service_url="   ")
        base_requirements: dict[str, Any] = {
            "amount": "1.00",
            "asset": "iso4217:USD",
            "payTo": "seller",
            "extra": {},
        }

        with pytest.raises(ValidationError, match="issuer"):
            await enhance_payment_requirements(base_requirements, signer)

    @pytest.mark.asyncio
    async def test_empty_issuer_does_not_sign(self) -> None:
        """Validation happens before signing, so the signer is never invoked."""
        signer = _FakeSigner(service_url="")
        base_requirements: dict[str, Any] = {
            "amount": "1.00",
            "asset": "iso4217:USD",
            "payTo": "seller",
            "extra": {},
        }

        with pytest.raises(ValidationError):
            await enhance_payment_requirements(base_requirements, signer)

        assert signer.last_payload is None
