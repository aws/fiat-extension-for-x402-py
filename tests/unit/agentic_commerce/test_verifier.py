# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for payment token verification."""

from __future__ import annotations

import time
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any, Optional

import boto3  # type: ignore[import-untyped]
import httpx
import jwt
import pytest
import respx
from moto import mock_aws

from fiat_extension_x402.agentic_commerce import verifier as verifier_module
from fiat_extension_x402.agentic_commerce.keys import (
    JwksSellerKeyResolver,
    KmsSellerKeyResolver,
    SellerKeyResolver,
    StaticSellerKeyResolver,
)
from fiat_extension_x402.agentic_commerce.quote import enhance_payment_requirements
from fiat_extension_x402.agentic_commerce.verifier import (
    AgenticCommerceVerifier,
    VerificationResult,
)
from fiat_extension_x402.constants import (
    DEFAULT_PAYMENT_TOKEN_JWKS_BASE_URL,
    PAYMENT_TOKEN_ISSUER,
    QUOTE_TOKEN_AUDIENCE,
)
from fiat_extension_x402.signers import KmsQuoteSigner, KmsQuoteSignerConfig, QuoteSigner
from tests.support import (
    SELLER_URL,
    SERVICE_JWKS_BASE_URL,
    FakePaymentService,
    ec_key,
    seller_signer,
)

SERVICE_JWKS_URL = f"{SERVICE_JWKS_BASE_URL}/.well-known/jwks.json"
SELLER_JWKS_URL = f"{SELLER_URL}/.well-known/jwks.json"
HMAC_SECRET = "a-shared-secret-that-is-at-least-32-bytes"


@pytest.fixture
def mock_router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def service(mock_router: respx.MockRouter) -> FakePaymentService:
    service = FakePaymentService()
    mock_router.get(SERVICE_JWKS_URL).mock(return_value=httpx.Response(200, json=service.jwks))
    return service


def _requirements(signer: QuoteSigner, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "scheme": "exact",
        "network": "aws:base",
        "asset": "iso4217:USD",
        "amount": "0.10",
        "payTo": "seller-1",
    }
    base.update(overrides)
    return enhance_payment_requirements(base, signer)


def _verifier(resolver: SellerKeyResolver, **kwargs: Any) -> AgenticCommerceVerifier:
    kwargs.setdefault("payment_token_jwks_url", SERVICE_JWKS_BASE_URL)
    return AgenticCommerceVerifier(seller_key_resolver=resolver, **kwargs)


def _static(signer: Any) -> AgenticCommerceVerifier:
    return _verifier(StaticSellerKeyResolver(signer.public_jwk))


def _service_token(
    service: FakePaymentService,
    claims: dict[str, Any],
    headers: Optional[dict[str, Any]] = None,
) -> str:
    token: str = jwt.encode(
        claims,
        service.private_key,
        algorithm="ES384",
        headers={"kid": service.jwk["kid"]} if headers is None else headers,
    )
    return token


def _payment_claims(quote_token: str, **overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": PAYMENT_TOKEN_ISSUER,
        "aud": SELLER_URL,
        "sub": "123456789012",
        "payment_id": "awsmp-1",
        "quote_token": quote_token,
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    return claims


def _quote_claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": SELLER_URL,
        "aud": QUOTE_TOKEN_AUDIENCE,
        "iat": now,
        "exp": now + 300,
        "jti": "quote-1",
        "price": {"amount": "0.10", "currency": "USD"},
        "payTo": "seller-1",
        "reference": "RESOURCE",
    }
    claims.update(overrides)
    return claims


def _raw_requirements(quote_token: str) -> dict[str, Any]:
    return {"amount": "0.10", "asset": "iso4217:USD", "extra": {"quoteToken": quote_token}}


def _assert_invalid(result: VerificationResult, reason: str, message: str) -> None:
    assert result.is_valid is False
    assert result.invalid_reason == reason
    assert result.invalid_message is not None
    assert message in result.invalid_message
    assert result.payer is None
    assert result.payment_id is None


class TestVerifySuccess:
    def test_valid_payment(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"], buyer="210987654321")

        result = _static(signer).verify(token, requirements)

        assert result.is_valid is True
        assert result.invalid_reason is None
        assert result.invalid_message is None
        assert result.payer == "210987654321"
        assert (
            result.payment_id
            == jwt.decode(token, options={"verify_signature": False})["payment_id"]
        )

    def test_non_usd_currency(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer, asset="iso4217:EUR", amount="2")
        token = service.issue(requirements["extra"]["quoteToken"])
        assert _static(signer).verify(token, requirements).is_valid is True

    def test_custom_payment_token_issuer(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"], issuer="issuer.test")
        verifier = _verifier(
            StaticSellerKeyResolver(signer.public_jwk), payment_token_issuer="issuer.test"
        )
        assert verifier.verify(token, requirements).is_valid is True

    def test_token_without_kid_uses_first_key(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = _service_token(
            service, _payment_claims(requirements["extra"]["quoteToken"]), headers={}
        )
        assert _static(signer).verify(token, requirements).is_valid is True

    def test_kid_selects_matching_key(self, mock_router: respx.MockRouter) -> None:
        service = FakePaymentService()
        _, other_jwk = ec_key("other-key")
        mock_router.get(SERVICE_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [other_jwk, service.jwk]})
        )
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        assert _static(signer).verify(token, requirements).is_valid is True


class TestRequirementsQuote:
    def test_missing_extra(self, service: FakePaymentService) -> None:
        result = _static(seller_signer()).verify("token", {"amount": "0.10"})
        _assert_invalid(result, "invalid_quote", "Missing quoteToken in payment requirements")

    def test_extra_none(self, service: FakePaymentService) -> None:
        result = _static(seller_signer()).verify("token", {"amount": "0.10", "extra": None})
        _assert_invalid(result, "invalid_quote", "Missing quoteToken in payment requirements")

    def test_empty_quote_token(self, service: FakePaymentService) -> None:
        result = _static(seller_signer()).verify("token", {"extra": {"quoteToken": ""}})
        _assert_invalid(result, "invalid_quote", "Missing quoteToken in payment requirements")


class TestPaymentTokenSignature:
    def test_signed_by_another_key(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        impostor = FakePaymentService()  # same kid, different key
        token = impostor.issue(requirements["extra"]["quoteToken"])
        result = _static(signer).verify(token, requirements)
        _assert_invalid(result, "invalid_payment", "Payment token signature invalid")

    def test_malformed_token(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        result = _static(signer).verify("not-a-jwt", _requirements(signer))
        _assert_invalid(result, "invalid_payment", "Payment token signature invalid")

    def test_jwks_fetch_http_error(self, mock_router: respx.MockRouter) -> None:
        mock_router.get(SERVICE_JWKS_URL).mock(return_value=httpx.Response(503))
        signer = seller_signer()
        requirements = _requirements(signer)
        token = FakePaymentService().issue(requirements["extra"]["quoteToken"])
        result = _static(signer).verify(token, requirements)
        _assert_invalid(result, "invalid_payment", "HTTP 503")

    def test_jwks_fetch_network_error(self, mock_router: respx.MockRouter) -> None:
        mock_router.get(SERVICE_JWKS_URL).mock(side_effect=httpx.ConnectError("unreachable"))
        signer = seller_signer()
        requirements = _requirements(signer)
        token = FakePaymentService().issue(requirements["extra"]["quoteToken"])
        result = _static(signer).verify(token, requirements)
        _assert_invalid(result, "invalid_payment", "unreachable")

    def test_no_matching_kid(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = _service_token(
            service,
            _payment_claims(requirements["extra"]["quoteToken"]),
            headers={"kid": "unknown-kid"},
        )
        result = _static(signer).verify(token, requirements)
        _assert_invalid(result, "invalid_payment", "No matching key found in JWKS")

    def test_empty_jwks(self, mock_router: respx.MockRouter) -> None:
        mock_router.get(SERVICE_JWKS_URL).mock(return_value=httpx.Response(200, json={}))
        signer = seller_signer()
        requirements = _requirements(signer)
        token = FakePaymentService().issue(requirements["extra"]["quoteToken"])
        result = _static(signer).verify(token, requirements)
        _assert_invalid(result, "invalid_payment", "No matching key found in JWKS")

    def test_disallowed_algorithm(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = jwt.encode(
            _payment_claims(requirements["extra"]["quoteToken"]),
            HMAC_SECRET,
            algorithm="HS256",
            headers={"kid": service.jwk["kid"]},
        )
        result = _static(signer).verify(token, requirements)
        _assert_invalid(result, "invalid_payment", "Algorithm not allowed: HS256")

    def test_service_jwks_fetched_on_every_verification(
        self, mock_router: respx.MockRouter
    ) -> None:
        service = FakePaymentService()
        route = mock_router.get(SERVICE_JWKS_URL).mock(
            return_value=httpx.Response(200, json=service.jwks)
        )
        signer = seller_signer()
        verifier = _static(signer)
        for _ in range(2):
            requirements = _requirements(signer)
            verifier.verify(service.issue(requirements["extra"]["quoteToken"]), requirements)
        assert route.call_count == 2


class TestServiceJwksRequest:
    def test_request_headers_are_sent(self, mock_router: respx.MockRouter) -> None:
        service = FakePaymentService()
        route = mock_router.get(SERVICE_JWKS_URL).mock(
            return_value=httpx.Response(200, json=service.jwks)
        )
        signer = seller_signer()
        requirements = _requirements(signer)
        verifier = _verifier(
            StaticSellerKeyResolver(signer.public_jwk),
            jwks_request_headers={"x-access-key": "onboarding-secret"},
        )
        result = verifier.verify(service.issue(requirements["extra"]["quoteToken"]), requirements)
        assert result.is_valid is True
        assert route.calls.last.request.headers["x-access-key"] == "onboarding-secret"

    def test_default_jwks_url(self, mock_router: respx.MockRouter) -> None:
        service = FakePaymentService()
        route = mock_router.get(
            f"{DEFAULT_PAYMENT_TOKEN_JWKS_BASE_URL}/.well-known/jwks.json"
        ).mock(return_value=httpx.Response(200, json=service.jwks))
        signer = seller_signer()
        requirements = _requirements(signer)
        verifier = AgenticCommerceVerifier(
            seller_key_resolver=StaticSellerKeyResolver(signer.public_jwk)
        )
        result = verifier.verify(service.issue(requirements["extra"]["quoteToken"]), requirements)
        assert result.is_valid is True
        assert route.call_count == 1

    def test_trailing_slash_in_jwks_url(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        verifier = _verifier(
            StaticSellerKeyResolver(signer.public_jwk),
            payment_token_jwks_url=f"{SERVICE_JWKS_BASE_URL}/",
        )
        result = verifier.verify(service.issue(requirements["extra"]["quoteToken"]), requirements)
        assert result.is_valid is True


class TestPaymentTokenClaims:
    def test_wrong_issuer(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"], issuer="someone-else.test")
        result = _static(signer).verify(token, requirements)
        _assert_invalid(
            result, "invalid_payment", "Payment token issuer is not the payment service"
        )

    def test_expired(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"], expires_in=-10)
        result = _static(signer).verify(token, requirements)
        _assert_invalid(result, "payment_expired", "Payment token expired")

    def test_missing_exp(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        claims = _payment_claims(requirements["extra"]["quoteToken"])
        del claims["exp"]
        result = _static(signer).verify(_service_token(service, claims), requirements)
        _assert_invalid(result, "payment_expired", "Payment token expired")

    def test_missing_quote_token_claim(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        claims = _payment_claims("unused")
        del claims["quote_token"]
        result = _static(signer).verify(_service_token(service, claims), requirements)
        _assert_invalid(result, "invalid_quote", "Missing quote token in payment token")

    def test_non_string_quote_token_claim(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        claims = _payment_claims("unused")
        claims["quote_token"] = {"not": "a string"}
        result = _static(signer).verify(_service_token(service, claims), requirements)
        _assert_invalid(result, "invalid_quote", "Missing quote token in payment token")

    def test_issued_for_a_different_quote(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        paid_for = _requirements(signer)
        current = _requirements(signer)
        token = service.issue(paid_for["extra"]["quoteToken"])
        result = _static(signer).verify(token, current)
        _assert_invalid(result, "invalid_quote", "Payment token was issued for a different quote")

    def test_audience_is_not_quote_issuer(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"], audience="https://other.test")
        result = _static(signer).verify(token, requirements)
        _assert_invalid(result, "invalid_payment", "Payment token audience is not the quote issuer")


class TestQuoteToken:
    def test_signed_by_another_seller_key(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        other = seller_signer()  # same kid, different key
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        result = _static(other).verify(token, requirements)
        _assert_invalid(result, "invalid_quote", "Quote token signature invalid")

    def test_disallowed_algorithm(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        quote = jwt.encode(
            _quote_claims(), HMAC_SECRET, algorithm="HS256", headers={"kid": "seller-key"}
        )
        token = service.issue(quote)
        result = _static(signer).verify(token, _raw_requirements(quote))
        _assert_invalid(result, "invalid_quote", "Algorithm not allowed: HS256")

    def test_expired(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        quote = signer.sign_quote(_quote_claims(exp=int(time.time()) - 10))
        result = _static(signer).verify(service.issue(quote), _raw_requirements(quote))
        _assert_invalid(result, "quote_expired", "Quote token expired")

    def test_missing_exp(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        claims = _quote_claims()
        del claims["exp"]
        quote = signer.sign_quote(claims)
        result = _static(signer).verify(service.issue(quote), _raw_requirements(quote))
        _assert_invalid(result, "quote_expired", "Quote token expired")

    def test_amount_mismatch(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        result = _static(signer).verify(token, {**requirements, "amount": "0.20"})
        _assert_invalid(result, "invalid_payment", "Amount or currency mismatch")

    def test_currency_mismatch(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        result = _static(signer).verify(token, {**requirements, "asset": "iso4217:EUR"})
        _assert_invalid(result, "invalid_payment", "Amount or currency mismatch")

    def test_missing_asset_is_a_currency_mismatch(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        del requirements["asset"]
        result = _static(signer).verify(token, requirements)
        _assert_invalid(result, "invalid_payment", "Amount or currency mismatch")

    def test_non_dict_price(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        quote = signer.sign_quote(_quote_claims(price="0.10 USD"))
        result = _static(signer).verify(service.issue(quote), _raw_requirements(quote))
        _assert_invalid(result, "invalid_payment", "Amount or currency mismatch")

    def test_missing_price(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        claims = _quote_claims()
        del claims["price"]
        quote = signer.sign_quote(claims)
        result = _static(signer).verify(service.issue(quote), _raw_requirements(quote))
        _assert_invalid(result, "invalid_payment", "Amount or currency mismatch")


class TestUnknownResolver:
    def test_unsupported_resolver_type(self, service: FakePaymentService) -> None:
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        verifier = AgenticCommerceVerifier(
            seller_key_resolver=SimpleNamespace(public_jwk=signer.public_jwk),  # type: ignore[arg-type]
            payment_token_jwks_url=SERVICE_JWKS_BASE_URL,
        )
        result = verifier.verify(token, requirements)
        _assert_invalid(result, "invalid_quote", "A seller key resolver is required")


class TestJwksSellerKeyResolver:
    def test_valid_and_cached_for_an_hour(
        self, mock_router: respx.MockRouter, service: FakePaymentService
    ) -> None:
        signer = seller_signer()
        seller_route = mock_router.get(SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [signer.public_jwk]})
        )
        verifier = _verifier(JwksSellerKeyResolver(SELLER_URL))

        for _ in range(2):
            requirements = _requirements(signer)
            token = service.issue(requirements["extra"]["quoteToken"])
            assert verifier.verify(token, requirements).is_valid is True

        assert seller_route.call_count == 1

    def test_refetched_after_cache_ttl(
        self,
        mock_router: respx.MockRouter,
        service: FakePaymentService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        signer = seller_signer()
        seller_route = mock_router.get(SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [signer.public_jwk]})
        )
        verifier = _verifier(JwksSellerKeyResolver(SELLER_URL))
        # Tokens outlive the clock jump below.
        requirements = _requirements(signer, maxTimeoutSeconds=10_000)
        token = service.issue(requirements["extra"]["quoteToken"], expires_in=10_000)

        assert verifier.verify(token, requirements).is_valid is True
        start = time.time()
        monkeypatch.setattr(verifier_module, "time", SimpleNamespace(time=lambda: start + 3601))
        assert verifier.verify(token, requirements).is_valid is True

        assert seller_route.call_count == 2

    def test_trailing_slash_in_jwks_url(
        self, mock_router: respx.MockRouter, service: FakePaymentService
    ) -> None:
        signer = seller_signer()
        mock_router.get(SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [signer.public_jwk]})
        )
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        verifier = _verifier(JwksSellerKeyResolver(f"{SELLER_URL}/"))
        assert verifier.verify(token, requirements).is_valid is True

    def test_seller_jwks_fetch_error(
        self, mock_router: respx.MockRouter, service: FakePaymentService
    ) -> None:
        mock_router.get(SELLER_JWKS_URL).mock(return_value=httpx.Response(404))
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        result = _verifier(JwksSellerKeyResolver(SELLER_URL)).verify(token, requirements)
        _assert_invalid(result, "invalid_quote", "HTTP 404")

    def test_seller_jwks_without_matching_kid(
        self, mock_router: respx.MockRouter, service: FakePaymentService
    ) -> None:
        _, other_jwk = ec_key("other-key")
        mock_router.get(SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [other_jwk]})
        )
        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        result = _verifier(JwksSellerKeyResolver(SELLER_URL)).verify(token, requirements)
        _assert_invalid(result, "invalid_quote", "No matching key found in JWKS")

    def test_seller_jwks_not_sent_service_headers(
        self, mock_router: respx.MockRouter, service: FakePaymentService
    ) -> None:
        signer = seller_signer()
        seller_route = mock_router.get(SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [signer.public_jwk]})
        )
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        verifier = _verifier(
            JwksSellerKeyResolver(SELLER_URL),
            jwks_request_headers={"x-access-key": "onboarding-secret"},
        )
        assert verifier.verify(token, requirements).is_valid is True
        assert "x-access-key" not in seller_route.calls.last.request.headers


@pytest.fixture
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(name, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


class _CountingKmsClient:
    """Wraps a KMS client and counts ``GetPublicKey`` calls."""

    def __init__(self, client: Any) -> None:
        self._client = client
        self.get_public_key_calls = 0

    def get_public_key(self, **kwargs: Any) -> Any:
        self.get_public_key_calls += 1
        return self._client.get_public_key(**kwargs)


@pytest.mark.usefixtures("aws_credentials")
class TestKmsSellerKeyResolver:
    @staticmethod
    def _kms_signer(client: Any) -> tuple[KmsQuoteSigner, str]:
        key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
        key_arn: str = key["KeyMetadata"]["Arn"]
        config = KmsQuoteSignerConfig(
            key_arn=key_arn, region="us-east-1", service_url=SELLER_URL, _kms_client=client
        )
        return KmsQuoteSigner(config), key_arn

    def test_valid_with_injected_client_and_cached(self, service: FakePaymentService) -> None:
        with mock_aws():
            client = boto3.client("kms", region_name="us-east-1")
            signer, key_arn = self._kms_signer(client)
            counting = _CountingKmsClient(client)
            verifier = _verifier(
                KmsSellerKeyResolver(kms_key_arn=key_arn, region="us-east-1", kms_client=counting)
            )

            for _ in range(2):
                requirements = _requirements(signer)
                token = service.issue(requirements["extra"]["quoteToken"])
                assert verifier.verify(token, requirements).is_valid is True

            assert counting.get_public_key_calls == 1

    def test_valid_with_ambient_credentials(self, service: FakePaymentService) -> None:
        with mock_aws():
            signer, key_arn = self._kms_signer(boto3.client("kms", region_name="us-east-1"))
            verifier = _verifier(KmsSellerKeyResolver(kms_key_arn=key_arn, region="us-east-1"))
            requirements = _requirements(signer)
            token = service.issue(requirements["extra"]["quoteToken"])
            assert verifier.verify(token, requirements).is_valid is True

    def test_valid_with_credentials_provider(self, service: FakePaymentService) -> None:
        calls: list[int] = []

        def credentials() -> Any:
            calls.append(1)
            return SimpleNamespace(access_key="AKIDTEST", secret_key="secret", token="session")

        with mock_aws():
            signer, key_arn = self._kms_signer(boto3.client("kms", region_name="us-east-1"))
            verifier = _verifier(
                KmsSellerKeyResolver(
                    kms_key_arn=key_arn, region="us-east-1", credentials=credentials
                )
            )
            requirements = _requirements(signer)
            token = service.issue(requirements["extra"]["quoteToken"])
            assert verifier.verify(token, requirements).is_valid is True
        assert calls == [1]

    def test_quote_signed_by_another_kms_key(self, service: FakePaymentService) -> None:
        with mock_aws():
            client = boto3.client("kms", region_name="us-east-1")
            signer, _ = self._kms_signer(client)
            _, other_arn = self._kms_signer(client)
            verifier = _verifier(
                KmsSellerKeyResolver(kms_key_arn=other_arn, region="us-east-1", kms_client=client)
            )
            requirements = _requirements(signer)
            token = service.issue(requirements["extra"]["quoteToken"])
            result = verifier.verify(token, requirements)
        _assert_invalid(result, "invalid_quote", "Quote token signature invalid")

    def test_no_public_key_returned(self, service: FakePaymentService) -> None:
        class _EmptyKmsClient:
            def get_public_key(self, **kwargs: Any) -> dict[str, Any]:
                return {}

        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        verifier = _verifier(
            KmsSellerKeyResolver(
                kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/none",
                region="us-east-1",
                kms_client=_EmptyKmsClient(),
            )
        )
        result = verifier.verify(token, requirements)
        _assert_invalid(result, "invalid_quote", "KMS GetPublicKey returned no key material")

    def test_kms_error_is_invalid_quote(self, service: FakePaymentService) -> None:
        class _FailingKmsClient:
            def get_public_key(self, **kwargs: Any) -> dict[str, Any]:
                raise RuntimeError("AccessDenied")

        signer = seller_signer()
        requirements = _requirements(signer)
        token = service.issue(requirements["extra"]["quoteToken"])
        verifier = _verifier(
            KmsSellerKeyResolver(
                kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/none",
                region="us-east-1",
                kms_client=_FailingKmsClient(),
            )
        )
        result = verifier.verify(token, requirements)
        _assert_invalid(result, "invalid_quote", "AccessDenied")


class TestKeyResolvers:
    def test_resolvers_are_frozen(self) -> None:
        resolver = StaticSellerKeyResolver({"kty": "EC"})
        with pytest.raises(AttributeError):
            resolver.public_jwk = {}  # type: ignore[misc]

    def test_kms_client_excluded_from_repr_and_equality(self) -> None:
        a = KmsSellerKeyResolver("arn", "us-east-1", kms_client=object())
        b = KmsSellerKeyResolver("arn", "us-east-1", kms_client=object())
        assert a == b
        assert "kms_client" not in repr(a)
