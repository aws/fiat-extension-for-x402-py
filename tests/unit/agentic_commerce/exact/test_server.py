# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the seller side of the ``exact`` scheme."""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from x402.schemas import AbortResult, AssetAmount, PaymentPayload, PaymentRequirements
from x402.schemas.hooks import VerifyContext

from fiat_extension_x402.agentic_commerce.exact import ExactAgenticCommerceServerScheme
from fiat_extension_x402.constants import (
    ASSET_TRANSFER_METHOD,
    DEFAULT_QUOTE_VALIDITY_SECONDS,
    SENTINEL_PAY_TO,
)
from fiat_extension_x402.exceptions import ValidationError
from tests.support import SELLER_URL, FakePaymentService, dpop_proof, ec_key, seller_signer

URL = f"{SELLER_URL}/weather"


class _FakeAdapter:
    """The subset of x402's HTTP adapter that the scheme uses."""

    def __init__(self, method: str, url: str, headers: dict[str, str] | None = None) -> None:
        self._method = method
        self._url = url
        self._headers = headers or {}

    def get_header(self, name: str) -> str | None:
        return self._headers.get(name)

    def get_method(self) -> str:
        return self._method

    def get_url(self) -> str:
        return self._url


class _InMemoryNonceStore:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    def has(self, jti: str) -> bool:
        return jti in self.seen

    def add(self, jti: str, expires_at: int) -> None:
        self.seen.add(jti)


def _scheme(**kwargs: Any) -> ExactAgenticCommerceServerScheme:
    return ExactAgenticCommerceServerScheme(signer=seller_signer(), **kwargs)


def _base_requirements() -> PaymentRequirements:
    return PaymentRequirements(
        scheme="exact",
        network="aws:base",
        asset="iso4217:USD",
        amount="0.10",
        pay_to="seller-1",
        max_timeout_seconds=DEFAULT_QUOTE_VALIDITY_SECONDS,
        extra={"description": "Weather"},
    )


def _context(
    payment_payload: dict[str, Any],
    adapter: _FakeAdapter | None = None,
    transport_context: Any = "unset",
) -> VerifyContext:
    requirements = _base_requirements()
    if transport_context == "unset":
        transport_context = SimpleNamespace(request=SimpleNamespace(adapter=adapter))
    return VerifyContext(
        payment_payload=PaymentPayload(payload=payment_payload, accepted=requirements),
        requirements=requirements,
        transport_context=transport_context,
    )


class _Buyer:
    """A buyer with a DPoP key and a payment token bound to it."""

    def __init__(self) -> None:
        self.key, self.jwk = ec_key("buyer")
        self.token = FakePaymentService().issue("quote", dpop_jwk=self.jwk)

    def proof(self, *, htm: str = "GET", htu: str = URL, **kwargs: Any) -> str:
        kwargs.setdefault("access_token", self.token)
        return dpop_proof(self.key, self.jwk, htm=htm, htu=htu, **kwargs)

    def context(
        self, headers: dict[str, str], method: str = "GET", url: str = URL
    ) -> VerifyContext:
        return _context({"paymentToken": self.token}, _FakeAdapter(method, url, headers))


class TestClassAttributes:
    def test_attributes(self) -> None:
        scheme = ExactAgenticCommerceServerScheme
        assert scheme.scheme == "exact"
        assert scheme.caip_family == "aws:*"
        assert scheme.default_asset_transfer_method == ASSET_TRANSFER_METHOD
        assert scheme.payment_flows == {
            ASSET_TRANSFER_METHOD: {"supported": ("authorization",), "default": "authorization"}
        }
        assert scheme.dynamic_extra_fields == ["quoteToken"]

    def test_signer_property(self) -> None:
        signer = seller_signer()
        assert ExactAgenticCommerceServerScheme(signer=signer).signer is signer


class TestParsePrice:
    @pytest.mark.parametrize(
        ("price", "amount", "asset"),
        [
            ("$1.50", "1.50", "iso4217:USD"),
            ("1.50 USD", "1.50", "iso4217:USD"),
            ("1.50", "1.50", "iso4217:USD"),
            ("  $3  ", "3", "iso4217:USD"),
            ("2 EUR", "2", "iso4217:EUR"),
            ("0.5JPY", "0.5", "iso4217:JPY"),
            (1.5, "1.5", "iso4217:USD"),
            (2, "2", "iso4217:USD"),
            (0, "0", "iso4217:USD"),
        ],
    )
    def test_parses(self, price: Any, amount: str, asset: str) -> None:
        parsed = _scheme().parse_price(price, "aws:base")
        assert parsed == AssetAmount(amount=amount, asset=asset, extra={})

    def test_asset_amount_passthrough(self) -> None:
        price = AssetAmount(amount="7", asset="iso4217:GBP", extra={"k": "v"})
        assert _scheme().parse_price(price, "aws:base") is price

    def test_dict_passthrough(self) -> None:
        price = {"amount": "7", "asset": "iso4217:GBP"}
        parsed = _scheme().parse_price(price, "aws:base")  # type: ignore[arg-type]
        assert parsed.amount == "7"
        assert parsed.asset == "iso4217:GBP"

    @pytest.mark.parametrize(
        "price", ["", "abc", "USD 1.50", "1.50 usd", "1.", "1,50", "-1.50", "$-1", "1.50 USDD"]
    )
    def test_invalid_string_raises(self, price: str) -> None:
        with pytest.raises(ValidationError, match="Invalid price"):
            _scheme().parse_price(price, "aws:base")

    @pytest.mark.parametrize("price", [-1.5, -1])
    def test_negative_number_raises(self, price: float) -> None:
        with pytest.raises(ValidationError, match="finite, non-negative"):
            _scheme().parse_price(price, "aws:base")

    def test_nan_raises(self) -> None:
        with pytest.raises(ValidationError, match="finite, non-negative"):
            _scheme().parse_price(float("nan"), "aws:base")

    def test_infinity_raises(self) -> None:
        with pytest.raises(ValidationError, match="finite, non-negative"):
            _scheme().parse_price(float("inf"), "aws:base")

    def test_small_float_uses_plain_decimal_notation(self) -> None:
        assert _scheme().parse_price(1e-7, "aws:base").amount == "0.0000001"

    def test_eight_decimal_places_accepted(self) -> None:
        assert _scheme().parse_price("$0.00000001", "aws:base").amount == "0.00000001"

    @pytest.mark.parametrize("price", ["$0.000000001", 1e-9])
    def test_more_than_eight_decimal_places_raises(self, price: Any) -> None:
        with pytest.raises(ValidationError, match="at most 8 decimal places"):
            _scheme().parse_price(price, "aws:base")


class TestEnhancePaymentRequirements:
    def test_returns_requirements_with_quote(self) -> None:
        signer = seller_signer()
        scheme = ExactAgenticCommerceServerScheme(signer=signer)
        enhanced = scheme.enhance_payment_requirements(_base_requirements())

        assert isinstance(enhanced, PaymentRequirements)
        assert enhanced.pay_to == SENTINEL_PAY_TO
        assert enhanced.max_timeout_seconds == DEFAULT_QUOTE_VALIDITY_SECONDS
        assert enhanced.extra["description"] == "Weather"
        claims = jwt.decode(
            enhanced.extra["quoteToken"],
            jwt.PyJWK.from_dict(signer.public_jwk).key,
            algorithms=["ES256"],
            options={"verify_aud": False},
        )
        assert claims["payTo"] == "seller-1"
        assert claims["price"] == {"amount": "0.10", "currency": "USD"}
        assert claims["description"] == "Weather"

    def test_accepts_supported_kind_and_extensions(self) -> None:
        enhanced = _scheme().enhance_payment_requirements(_base_requirements(), None, ["ext"])
        assert "quoteToken" in enhanced.extra


class TestBeforeVerifyUnboundTokens:
    def test_no_payment_token(self) -> None:
        assert _scheme().before_verify(_context({})) is None

    def test_non_string_payment_token(self) -> None:
        assert _scheme().before_verify(_context({"paymentToken": 123})) is None

    def test_malformed_payment_token(self) -> None:
        assert _scheme().before_verify(_context({"paymentToken": "not-a-jwt"})) is None

    def test_token_without_cnf(self) -> None:
        token = FakePaymentService().issue("quote")
        assert _scheme().before_verify(_context({"paymentToken": token})) is None

    @pytest.mark.parametrize("cnf", ["jkt", {"x5t#S256": "abc"}])
    def test_token_with_unusable_cnf(self, cnf: Any) -> None:
        token = jwt.encode({"cnf": cnf}, "a-shared-secret-that-is-at-least-32-bytes")
        assert _scheme().before_verify(_context({"paymentToken": token})) is None


class TestBeforeVerifyDpopRequired:
    def test_no_transport_context(self) -> None:
        buyer = _Buyer()
        context = _context({"paymentToken": buyer.token}, transport_context=None)
        assert _scheme().before_verify(context) == AbortResult(reason="dpop_required")

    def test_no_adapter(self) -> None:
        buyer = _Buyer()
        context = _context({"paymentToken": buyer.token}, adapter=None)
        assert _scheme().before_verify(context) == AbortResult(reason="dpop_required")

    def test_no_dpop_header(self) -> None:
        assert _scheme().before_verify(_Buyer().context({})) == AbortResult(reason="dpop_required")

    def test_empty_dpop_header(self) -> None:
        result = _scheme().before_verify(_Buyer().context({"DPoP": ""}))
        assert result == AbortResult(reason="dpop_required")


class TestBeforeVerifyDpopProof:
    def test_valid_proof(self) -> None:
        buyer = _Buyer()
        assert _scheme().before_verify(buyer.context({"DPoP": buyer.proof()})) is None

    def test_lowercase_header_name(self) -> None:
        buyer = _Buyer()
        assert _scheme().before_verify(buyer.context({"dpop": buyer.proof()})) is None

    def test_method_is_compared_upper_case(self) -> None:
        buyer = _Buyer()
        context = buyer.context({"DPoP": buyer.proof(htm="POST")}, method="post")
        assert _scheme().before_verify(context) is None

    def test_query_and_fragment_stripped_from_htu(self) -> None:
        buyer = _Buyer()
        context = buyer.context({"DPoP": buyer.proof()}, url=f"{URL}?city=Seattle#today")
        assert _scheme().before_verify(context) is None

    def test_thumbprint_mismatch(self) -> None:
        buyer = _Buyer()
        other_key, other_jwk = ec_key("other")
        proof = dpop_proof(other_key, other_jwk, htm="GET", htu=URL, access_token=buyer.token)
        result = _scheme().before_verify(buyer.context({"DPoP": proof}))
        assert result == AbortResult(reason="dpop_invalid")

    def test_malformed_proof(self) -> None:
        result = _scheme().before_verify(_Buyer().context({"DPoP": "not-a-jwt"}))
        assert result == AbortResult(reason="dpop_invalid")

    def test_htm_mismatch(self) -> None:
        buyer = _Buyer()
        context = buyer.context({"DPoP": buyer.proof(htm="POST")}, method="GET")
        assert _scheme().before_verify(context) == AbortResult(reason="dpop_invalid")

    def test_htu_mismatch(self) -> None:
        buyer = _Buyer()
        context = buyer.context({"DPoP": buyer.proof(htu=f"{SELLER_URL}/other")})
        assert _scheme().before_verify(context) == AbortResult(reason="dpop_invalid")

    def test_proof_for_another_token(self) -> None:
        buyer = _Buyer()
        context = buyer.context({"DPoP": buyer.proof(access_token="another-token")})
        assert _scheme().before_verify(context) == AbortResult(reason="dpop_invalid")

    def test_proof_older_than_max_age(self) -> None:
        buyer = _Buyer()
        proof = buyer.proof(iat=int(time.time()) - 30)
        assert _scheme().before_verify(buyer.context({"DPoP": proof})) is None
        result = _scheme(dpop_max_age_seconds=10).before_verify(buyer.context({"DPoP": proof}))
        assert result == AbortResult(reason="dpop_invalid")

    def test_replay_rejected_with_nonce_store(self) -> None:
        buyer = _Buyer()
        scheme = _scheme(dpop_nonce_store=_InMemoryNonceStore())
        proof = buyer.proof()
        assert scheme.before_verify(buyer.context({"DPoP": proof})) is None
        assert scheme.before_verify(buyer.context({"DPoP": proof})) == AbortResult(
            reason="dpop_invalid"
        )

    def test_replay_allowed_without_nonce_store(self) -> None:
        buyer = _Buyer()
        scheme = _scheme()
        proof = buyer.proof()
        assert scheme.before_verify(buyer.context({"DPoP": proof})) is None
        assert scheme.before_verify(buyer.context({"DPoP": proof})) is None
