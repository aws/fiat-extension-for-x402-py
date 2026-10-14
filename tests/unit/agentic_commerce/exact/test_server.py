# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the seller side of the ``exact`` scheme."""

from __future__ import annotations

import gc
import time
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from x402 import x402FacilitatorSync, x402ResourceServerSync
from x402.schemas import (
    AbortResult,
    AssetAmount,
    PaymentPayload,
    PaymentRequirements,
    ResourceConfig,
    VerifyResponse,
)
from x402.schemas.hooks import VerifyContext, VerifyResultContext

from fiat_extension_x402 import (
    AgenticCommerceVerifier,
    StaticSellerKeyResolver,
    register_exact_agentic_commerce_facilitator,
    register_exact_agentic_commerce_server,
)
from fiat_extension_x402.agentic_commerce.exact import ExactAgenticCommerceServerScheme
from fiat_extension_x402.constants import (
    ASSET_TRANSFER_METHOD,
    DEFAULT_QUOTE_VALIDITY_SECONDS,
    SENTINEL_PAY_TO,
)
from fiat_extension_x402.exceptions import ValidationError
from tests.support import (
    SELLER_URL,
    SERVICE_JWKS_BASE_URL,
    FakePaymentService,
    dpop_proof,
    ec_key,
    seller_signer,
)

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


class _RecordingNonceStore:
    """Replay store that logs every call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.added: dict[str, int] = {}

    def has(self, jti: str) -> bool:
        self.calls.append(("has", jti))
        return jti in self.added

    def add(self, jti: str, expires_at: int) -> None:
        self.calls.append(("add", jti))
        self.added[jti] = expires_at


class _CheckAndSetNonceStore(_RecordingNonceStore):
    """Replay store whose ``has`` records the id: an atomic check-and-set."""

    def has(self, jti: str) -> bool:
        seen = super().has(jti)
        self.added.setdefault(jti, 0)
        return seen


class _FailingNonceStore:
    def __init__(self, failing: str) -> None:
        self.failing = failing

    def has(self, jti: str) -> bool:
        if self.failing == "has":
            raise RuntimeError(f"store unavailable for {jti}")
        return False

    def add(self, jti: str, expires_at: int) -> None:
        raise RuntimeError(f"store unavailable for {jti}")


class _EvictingNonceStore:
    """Replay store that forgets a proof id as soon as ``time.time()`` reaches its expiry."""

    def __init__(self) -> None:
        self.seen: dict[str, int] = {}

    def has(self, jti: str) -> bool:
        expires_at = self.seen.get(jti)
        return expires_at is not None and time.time() < expires_at

    def add(self, jti: str, expires_at: int) -> None:
        self.seen[jti] = expires_at


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


class _Transport:
    """A transport context, built for each request as x402 core does."""

    def __init__(self, adapter: _FakeAdapter | None) -> None:
        self.request = SimpleNamespace(adapter=adapter)


def _context(
    payment_payload: dict[str, Any],
    adapter: _FakeAdapter | None = None,
    transport_context: Any = "unset",
) -> VerifyContext:
    requirements = _base_requirements()
    if transport_context == "unset":
        transport_context = _Transport(adapter)
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


def _verified(context: VerifyContext, *, is_valid: bool = True) -> VerifyResultContext:
    """The context x402 core passes to ``after_verify`` once the facilitator answers."""
    return VerifyResultContext(
        payment_payload=context.payment_payload,
        requirements=context.requirements,
        transport_context=context.transport_context,
        result=VerifyResponse(is_valid=is_valid, invalid_reason=None if is_valid else "invalid"),
    )


def _pay(
    scheme: ExactAgenticCommerceServerScheme, context: VerifyContext, *, is_valid: bool = True
) -> AbortResult | None:
    """Run both hooks as x402 core does: ``after_verify`` only if ``before_verify`` passes."""
    result = scheme.before_verify(context)
    if result is not None:
        return result
    return scheme.after_verify(_verified(context, is_valid=is_valid))


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

    def test_x402_core_finds_both_hooks(self) -> None:
        from x402.hook_adapters import collect_scheme_server_hook_handles

        scheme: Any = _scheme()  # Not typed as x402's SchemeNetworkServer protocol.
        handles = collect_scheme_server_hook_handles(scheme)
        assert handles.before_verify == scheme.before_verify
        assert handles.after_verify == scheme.after_verify

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
        "price",
        [
            "",
            "abc",
            "USD 1.50",
            "1.50 usd",
            "1.",
            "1,50",
            "-1.50",
            "$-1",
            "1.50 USDD",
            "\u0661.\u0665\u0660",
            "$1.\u0665",
        ],
    )
    def test_invalid_string_raises(self, price: str) -> None:
        with pytest.raises(ValidationError, match="Invalid price"):
            _scheme().parse_price(price, "aws:base")

    @pytest.mark.parametrize("price", [True, False])
    def test_boolean_raises(self, price: bool) -> None:
        with pytest.raises(ValidationError) as raised:
            _scheme().parse_price(price, "aws:base")
        assert str(raised.value) == f"Invalid price: {price!r}"

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

    def test_negative_zero_is_zero(self) -> None:
        assert _scheme().parse_price(-0.0, "aws:base").amount == "0.0"

    @pytest.mark.parametrize("price", ["$1.50", "2 EUR", "  $3  ", 1.5, 2, 0, -0.0, 1e-8, 1e20])
    def test_parsed_price_passes_the_signing_check(self, price: Any) -> None:
        scheme = _scheme()
        parsed = scheme.parse_price(price, "aws:base")
        requirements = _base_requirements().model_copy(
            update={"amount": parsed.amount, "asset": parsed.asset}
        )
        assert scheme.enhance_payment_requirements(requirements).amount == parsed.amount

    def test_small_float_uses_plain_decimal_notation(self) -> None:
        assert _scheme().parse_price(1e-7, "aws:base").amount == "0.0000001"

    def test_eight_decimal_places_accepted(self) -> None:
        assert _scheme().parse_price("$0.00000001", "aws:base").amount == "0.00000001"

    @pytest.mark.parametrize("price", ["$0.000000001", 1e-9])
    def test_more_than_eight_decimal_places_raises(self, price: Any) -> None:
        with pytest.raises(ValidationError, match="at most 8 decimal places"):
            _scheme().parse_price(price, "aws:base")


class _Unrepresentable:
    def __repr__(self) -> str:
        raise RuntimeError("no repr")


def _shown(amount: Any, asset: Any) -> str:
    return repr({"amount": amount, "asset": asset})


class TestParseObjectPrice:
    """An ``AssetAmount`` or ``{amount, asset}`` price follows the string-price rules."""

    @pytest.mark.parametrize(
        "amount", ["0", "1.50", "01.50", "0.00000001", "99.99999990", "1" * 30]
    )
    def test_amount_passes_through(self, amount: str) -> None:
        price = AssetAmount(amount=amount, asset="iso4217:USD")
        assert _scheme().parse_price(price, "aws:base") is price
        parsed = _scheme().parse_price({"amount": amount, "asset": "iso4217:USD"}, "aws:base")  # type: ignore[arg-type]
        assert parsed == AssetAmount(amount=amount, asset="iso4217:USD")

    @pytest.mark.parametrize("asset", ["iso4217:EUR", "iso4217:JPY"])
    def test_asset_accepted(self, asset: str) -> None:
        price = AssetAmount(amount="1", asset=asset, extra={"k": "v"})
        assert _scheme().parse_price(price, "aws:base") is price

    @pytest.mark.parametrize("amount", ["0.123456789", "1.000000000", "0.000000001"])
    @pytest.mark.parametrize("as_dict", [False, True])
    def test_more_than_eight_decimal_places_raises(self, amount: str, as_dict: bool) -> None:
        price: Any = {"amount": amount, "asset": "iso4217:USD"}
        with pytest.raises(ValidationError) as raised:
            _scheme().parse_price(price if as_dict else AssetAmount(**price), "aws:base")
        assert str(raised.value) == (
            f"Price may have at most 8 decimal places: {_shown(amount, 'iso4217:USD')}"
        )

    @pytest.mark.parametrize(
        "amount",
        [
            "1e5",
            "1E5",
            "1.5e-3",
            "-1",
            "-0",
            "+1",
            "",
            " ",
            " 1.50",
            "1.50 ",
            "1.50\n",
            "1.",
            ".5",
            "1,50",
            "1_000",
            "0x10",
            "NaN",
            "Infinity",
            "$1.50",
            "1.50 USD",
            "\u0661",
            "1.\u0665",
        ],
    )
    @pytest.mark.parametrize("as_dict", [False, True])
    def test_amount_not_a_plain_decimal_raises(self, amount: str, as_dict: bool) -> None:
        price: Any = {"amount": amount, "asset": "iso4217:USD"}
        with pytest.raises(ValidationError) as raised:
            _scheme().parse_price(price if as_dict else AssetAmount(**price), "aws:base")
        assert str(raised.value) == f"Invalid price: {_shown(amount, 'iso4217:USD')}"

    @pytest.mark.parametrize(
        "asset",
        [
            "",
            "USD",
            "iso4217:usd",
            "iso4217:US",
            "iso4217:USDD",
            "iso4217:iso4217:USD",
            " iso4217:USD",
            "iso4217:USD\n",
            "ISO4217:USD",
            "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        ],
    )
    @pytest.mark.parametrize("as_dict", [False, True])
    def test_asset_not_iso4217_raises(self, asset: str, as_dict: bool) -> None:
        price: Any = {"amount": "1.50", "asset": asset}
        with pytest.raises(ValidationError) as raised:
            _scheme().parse_price(price if as_dict else AssetAmount(**price), "aws:base")
        assert str(raised.value) == f"Invalid price: {_shown('1.50', asset)}"

    @pytest.mark.parametrize(
        "price",
        [
            {"amount": 1.5, "asset": "iso4217:USD"},
            {"amount": 1, "asset": "iso4217:USD"},
            {"amount": "1", "asset": None},
            {"amount": "1"},
            {"asset": "iso4217:USD"},
            {},
        ],
    )
    def test_dict_field_missing_or_not_a_string_raises(self, price: dict[str, Any]) -> None:
        with pytest.raises(ValidationError) as raised:
            _scheme().parse_price(price, "aws:base")  # type: ignore[arg-type]
        assert str(raised.value) == (
            f"Invalid price: {_shown(price.get('amount'), price.get('asset'))}"
        )

    def test_unvalidated_asset_amount_raises(self) -> None:
        price = AssetAmount.model_construct(amount=1.5, asset="iso4217:USD")
        with pytest.raises(ValidationError) as raised:
            _scheme().parse_price(price, "aws:base")
        assert str(raised.value) == f"Invalid price: {_shown(1.5, 'iso4217:USD')}"

    @pytest.mark.parametrize("as_dict", [False, True])
    def test_message_leaves_out_extra(self, as_dict: bool) -> None:
        price: Any = {"amount": "1.50", "asset": "usd", "extra": {"secret": "s3cr3t"}}
        with pytest.raises(ValidationError) as raised:
            _scheme().parse_price(price if as_dict else AssetAmount(**price), "aws:base")
        assert str(raised.value) == "Invalid price: {'amount': '1.50', 'asset': 'usd'}"

    @pytest.mark.parametrize("extra", ["s3cr3t", ["s3cr3t"], 7])
    def test_dict_extra_not_a_dict_raises_without_showing_it(self, extra: Any) -> None:
        price = {"amount": "1.50", "asset": "iso4217:USD", "extra": extra}
        with pytest.raises(ValidationError) as raised:
            _scheme().parse_price(price, "aws:base")  # type: ignore[arg-type]
        assert str(raised.value) == f"Invalid price: {_shown('1.50', 'iso4217:USD')}"
        assert raised.value.__cause__ is None
        assert raised.value.__suppress_context__

    def test_dict_extra_none_accepted(self) -> None:
        price = {"amount": "1.50", "asset": "iso4217:USD", "extra": None}
        parsed = _scheme().parse_price(price, "aws:base")  # type: ignore[arg-type]
        assert parsed == AssetAmount(amount="1.50", asset="iso4217:USD", extra=None)

    def test_unrepresentable_field_is_not_shown(self) -> None:
        price = {"amount": _Unrepresentable(), "asset": "iso4217:USD"}
        with pytest.raises(ValidationError) as raised:
            _scheme().parse_price(price, "aws:base")  # type: ignore[arg-type]
        assert str(raised.value) == "Invalid price: (not representable)"

    def test_bad_price_signs_no_quote_through_the_resource_server(self) -> None:
        """The first 402 for a route with a malformed object price is an error, not a quote."""
        signer = seller_signer()
        facilitator = register_exact_agentic_commerce_facilitator(
            x402FacilitatorSync(),
            verifier=AgenticCommerceVerifier(
                seller_key_resolver=StaticSellerKeyResolver(signer.public_jwk),
                payment_token_jwks_url=SERVICE_JWKS_BASE_URL,
            ),
        )
        server = register_exact_agentic_commerce_server(
            x402ResourceServerSync(facilitator), signer=signer
        )
        server.initialize()

        def build(price: Any) -> list[PaymentRequirements]:
            config = ResourceConfig(
                scheme="exact", pay_to="seller-1", price=price, network="aws:base"
            )
            return server.build_payment_requirements(config)

        good = build(AssetAmount(amount="0.10", asset="iso4217:EUR"))[0]
        claims = jwt.decode(good.extra["quoteToken"], options={"verify_signature": False})
        assert claims["price"] == {"amount": "0.10", "currency": "EUR"}
        for bad in (
            AssetAmount(amount="0.123456789", asset="iso4217:USD"),
            AssetAmount(amount="1e5", asset="iso4217:USD"),
            AssetAmount(amount="1", asset="USD"),
            {"amount": "1", "asset": "iso4217:iso4217:GBP"},
        ):
            with pytest.raises(ValidationError):
                build(bad)


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
        assert _pay(scheme, buyer.context({"DPoP": proof})) is None
        assert _pay(scheme, buyer.context({"DPoP": proof})) == AbortResult(reason="dpop_invalid")

    @pytest.mark.parametrize("max_age", [60, 10])
    def test_replay_rejected_for_the_whole_acceptance_window(
        self, max_age: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        buyer = _Buyer()
        scheme = _scheme(dpop_nonce_store=_EvictingNonceStore(), dpop_max_age_seconds=max_age)
        iat = 1_700_000_000
        # Accepted up to 5 seconds (clock skew) past the maximum age.
        last_accepted = iat + max_age + 5
        clock = {"now": float(iat)}
        monkeypatch.setattr(time, "time", lambda: clock["now"])
        proof = buyer.proof(iat=iat)
        assert _pay(scheme, buyer.context({"DPoP": proof})) is None

        replayed = {}
        for second in range(iat, last_accepted + 2):
            for now in (second, second + 0.5):
                clock["now"] = now
                replayed[now - iat] = _pay(scheme, buyer.context({"DPoP": proof}))
        assert replayed == dict.fromkeys(replayed, AbortResult(reason="dpop_invalid"))

        clock["now"] = last_accepted + 0.5
        fresh = buyer.proof(iat=iat)
        assert _pay(scheme, buyer.context({"DPoP": fresh})) is None
        assert _pay(scheme, buyer.context({"DPoP": fresh})) == AbortResult(reason="dpop_invalid")

    def test_replay_allowed_without_nonce_store(self) -> None:
        buyer = _Buyer()
        scheme = _scheme()
        proof = buyer.proof()
        assert _pay(scheme, buyer.context({"DPoP": proof})) is None
        assert _pay(scheme, buyer.context({"DPoP": proof})) is None


class TestNonceStoreAfterVerify:
    """A proof id is checked and recorded only once the facilitator accepts the token."""

    def test_before_verify_leaves_the_store_untouched(self) -> None:
        buyer = _Buyer()
        store = _RecordingNonceStore()
        scheme = _scheme(dpop_nonce_store=store)
        proof = buyer.proof()
        assert scheme.before_verify(buyer.context({"DPoP": proof})) is None
        assert scheme.before_verify(buyer.context({"DPoP": proof})) is None
        assert store.calls == []

    def test_forged_token_adds_nothing(self) -> None:
        """A token bound to the caller's own key, which the facilitator rejects."""
        store = _RecordingNonceStore()
        scheme = _scheme(dpop_nonce_store=store)
        for _ in range(20):
            forger = _Buyer()  # Its token is signed by a key the service never published.
            assert _pay(scheme, forger.context({"DPoP": forger.proof()}), is_valid=False) is None
        assert store.calls == []

    def test_accepted_token_records_the_id_once_with_its_expiry(self) -> None:
        buyer = _Buyer()
        store = _RecordingNonceStore()
        scheme = _scheme(dpop_nonce_store=store, dpop_max_age_seconds=10)
        iat = int(time.time())
        proof = buyer.proof(iat=iat)
        assert _pay(scheme, buyer.context({"DPoP": proof})) is None
        jti = jwt.decode(proof, options={"verify_signature": False})["jti"]
        assert store.calls == [("has", jti), ("add", jti)]
        assert store.added == {jti: iat + 10 + 5 + 1}

        assert _pay(scheme, buyer.context({"DPoP": proof})) == AbortResult(reason="dpop_invalid")
        assert store.calls[2:] == [("has", jti)]

    def test_store_that_records_in_has(self) -> None:
        buyer = _Buyer()
        store = _CheckAndSetNonceStore()
        scheme = _scheme(dpop_nonce_store=store)
        forger = _Buyer()
        assert _pay(scheme, forger.context({"DPoP": forger.proof()}), is_valid=False) is None
        assert store.added == {}

        proof = buyer.proof()
        assert _pay(scheme, buyer.context({"DPoP": proof})) is None
        assert _pay(scheme, buyer.context({"DPoP": proof})) == AbortResult(reason="dpop_invalid")
        assert [call[0] for call in store.calls] == ["has", "add", "has"]

    def test_proof_gone_stale_while_the_facilitator_ran(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        buyer = _Buyer()
        store = _RecordingNonceStore()
        scheme = _scheme(dpop_nonce_store=store)
        iat = 1_700_000_000
        clock = {"now": float(iat + 65)}
        monkeypatch.setattr(time, "time", lambda: clock["now"])
        context = buyer.context({"DPoP": buyer.proof(iat=iat)})
        assert scheme.before_verify(context) is None  # Still accepted at iat + 65.
        clock["now"] = iat + 66.0
        assert scheme.after_verify(_verified(context)) == AbortResult(reason="dpop_invalid")
        assert store.calls == []

    def test_proof_gone_stale_during_the_store_lookup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A store that has just forgotten the proof's earlier use must not let it pass."""
        buyer = _Buyer()
        iat = 1_700_000_000
        clock = {"now": float(iat + 65)}
        monkeypatch.setattr(time, "time", lambda: clock["now"])

        class _SlowEvictingStore(_EvictingNonceStore):
            def has(self, jti: str) -> bool:
                clock["now"] = iat + 66.0  # The lookup ends as the proof goes stale.
                return super().has(jti)

        store = _SlowEvictingStore()
        scheme = _scheme(dpop_nonce_store=store)
        context = buyer.context({"DPoP": buyer.proof(iat=iat)})
        assert scheme.before_verify(context) is None
        assert scheme.after_verify(_verified(context)) == AbortResult(reason="dpop_invalid")
        assert store.seen == {}

    def test_proof_accepted_in_its_last_second(self, monkeypatch: pytest.MonkeyPatch) -> None:
        buyer = _Buyer()
        scheme = _scheme(dpop_nonce_store=_RecordingNonceStore())
        iat = 1_700_000_000
        monkeypatch.setattr(time, "time", lambda: iat + 65.9)
        assert _pay(scheme, buyer.context({"DPoP": buyer.proof(iat=iat)})) is None

    @pytest.mark.parametrize("failing", ["has", "add"])
    def test_store_error_refuses_the_payment(
        self, failing: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        buyer = _Buyer()
        scheme = _scheme(dpop_nonce_store=_FailingNonceStore(failing))
        proof = buyer.proof()
        result = _pay(scheme, buyer.context({"DPoP": proof}))
        assert result == AbortResult(reason="dpop_invalid")
        assert caplog.messages == ["DPoP nonce store failed (RuntimeError); payment refused"]
        jti = jwt.decode(proof, options={"verify_signature": False})["jti"]
        assert jti not in caplog.text

    def test_each_request_keeps_its_own_proof(self) -> None:
        first, second = _Buyer(), _Buyer()
        store = _RecordingNonceStore()
        scheme = _scheme(dpop_nonce_store=store)
        first_proof, second_proof = first.proof(), second.proof()
        first_context = first.context({"DPoP": first_proof})
        second_context = second.context({"DPoP": second_proof})
        assert scheme.before_verify(first_context) is None
        assert scheme.before_verify(second_context) is None
        # The second request's token is rejected; the first one's is accepted.
        assert scheme.after_verify(_verified(second_context, is_valid=False)) is None
        assert scheme.after_verify(_verified(first_context)) is None
        first_jti = jwt.decode(first_proof, options={"verify_signature": False})["jti"]
        assert list(store.added) == [first_jti]

    def test_after_verify_runs_once_per_proof(self) -> None:
        buyer = _Buyer()
        store = _RecordingNonceStore()
        scheme = _scheme(dpop_nonce_store=store)
        context = buyer.context({"DPoP": buyer.proof()})
        assert scheme.before_verify(context) is None
        assert scheme.after_verify(_verified(context)) is None
        assert scheme.after_verify(_verified(context)) is None
        assert len(store.calls) == 2

    def test_reused_transport_context_drops_an_earlier_proof(self) -> None:
        buyer = _Buyer()
        store = _RecordingNonceStore()
        scheme = _scheme(dpop_nonce_store=store)
        transport = _Transport(_FakeAdapter("GET", URL, {"DPoP": buyer.proof()}))
        bound = _context({"paymentToken": buyer.token}, transport_context=transport)
        assert scheme.before_verify(bound) is None
        unbound = _context({"paymentToken": FakePaymentService().issue("quote")}, None, transport)
        assert scheme.before_verify(unbound) is None
        assert scheme.after_verify(_verified(unbound)) is None
        assert store.calls == []

    def test_unbound_token_and_no_before_verify(self) -> None:
        store = _RecordingNonceStore()
        scheme = _scheme(dpop_nonce_store=store)
        context = _context({"paymentToken": FakePaymentService().issue("quote")})
        assert _pay(scheme, context) is None
        assert scheme.after_verify(_verified(_Buyer().context({}))) is None
        assert store.calls == []

    def test_request_that_never_reaches_after_verify_leaves_nothing(self) -> None:
        buyer = _Buyer()
        scheme = _scheme(dpop_nonce_store=_RecordingNonceStore())
        for _ in range(5):
            assert scheme.before_verify(buyer.context({"DPoP": buyer.proof()})) is None
        gc.collect()
        assert scheme._pending_proofs._by_id == {}

    def test_transport_context_without_weak_references(self) -> None:
        buyer = _Buyer()
        adapter = _FakeAdapter("GET", URL, {"DPoP": buyer.proof()})
        transport = SimpleNamespace(request=SimpleNamespace(adapter=adapter))
        context = _context({"paymentToken": buyer.token}, transport_context=transport)
        assert _scheme().before_verify(context) is None
        store = _RecordingNonceStore()
        result = _scheme(dpop_nonce_store=store).before_verify(context)
        assert result == AbortResult(reason="dpop_invalid")
        assert store.calls == []
