# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A seller protected by x402 core's own HTTP middleware, end to end.

The seller registers this package's ``exact`` schemes on x402 core objects and
uses x402's FastAPI and Flask middleware unchanged. Payment tokens are minted by
a fake payment service whose JWKS is served through ``respx``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec
from x402 import x402Facilitator, x402FacilitatorSync, x402ResourceServer, x402ResourceServerSync
from x402.http.types import PaymentOption, RouteConfig

from fiat_extension_x402 import (
    AgenticCommerceVerifier,
    StaticSellerKeyResolver,
    register_exact_agentic_commerce_facilitator,
    register_exact_agentic_commerce_server,
)
from tests.support import (
    SERVICE_JWKS_BASE_URL,
    FakePaymentService,
    decode_header,
    dpop_proof,
    ec_key,
    encode_header,
    seller_signer,
)

ROUTES = {
    "GET /weather": RouteConfig(
        accepts=PaymentOption(scheme="exact", network="aws:base", pay_to="seller-1", price="$0.10"),
        description="Weather",
    ),
    "GET /ping": RouteConfig(
        accepts=PaymentOption(scheme="exact", network="aws:base", pay_to="seller-1", price="$0.01"),
        description="Ping",
    ),
}


@pytest.fixture
def service() -> Iterator[FakePaymentService]:
    service = FakePaymentService()
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{SERVICE_JWKS_BASE_URL}/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=service.jwks)
        )
        mock.route(host="testserver").pass_through()
        mock.route(host="localhost").pass_through()
        yield service


def _verifier(signer: Any) -> AgenticCommerceVerifier:
    return AgenticCommerceVerifier(
        seller_key_resolver=StaticSellerKeyResolver(signer.public_jwk),
        payment_token_jwks_url=SERVICE_JWKS_BASE_URL,
    )


def fastapi_client(signer: Any) -> Any:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from x402.http.middleware.fastapi import payment_middleware

    facilitator = register_exact_agentic_commerce_facilitator(
        x402Facilitator(), verifier=_verifier(signer)
    )
    server = register_exact_agentic_commerce_server(x402ResourceServer(facilitator), signer=signer)
    app = FastAPI()

    @app.get("/weather")
    def weather() -> dict[str, int]:
        return {"temp": 72}

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"pong": "ok"}

    app.middleware("http")(payment_middleware(ROUTES, server))
    return TestClient(app)


def flask_client(signer: Any) -> Any:
    from flask import Flask
    from x402.http.middleware.flask import payment_middleware

    facilitator = register_exact_agentic_commerce_facilitator(
        x402FacilitatorSync(), verifier=_verifier(signer)
    )
    server = register_exact_agentic_commerce_server(
        x402ResourceServerSync(facilitator), signer=signer
    )
    app = Flask(__name__)

    @app.get("/weather")
    def weather() -> dict[str, int]:
        return {"temp": 72}

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"pong": "ok"}

    payment_middleware(app, ROUTES, server)
    return app.test_client()


@pytest.fixture(params=["fastapi", "flask"])
def seller(request: pytest.FixtureRequest, service: FakePaymentService) -> Any:
    signer = seller_signer()
    return fastapi_client(signer) if request.param == "fastapi" else flask_client(signer)


def _offer(client: Any, path: str) -> dict[str, Any]:
    response = client.get(path)
    assert response.status_code == 402
    payment_required = decode_header(response.headers["PAYMENT-REQUIRED"])
    return payment_required


def _pay(client: Any, path: str, accepted: dict[str, Any], token: str, **headers: str) -> Any:
    payload = {"x402Version": 2, "accepted": accepted, "payload": {"paymentToken": token}}
    return client.get(path, headers={"PAYMENT-SIGNATURE": encode_header(payload), **headers})


class TestPaymentRequired:
    def test_unpaid_request_gets_exact_requirements_with_a_quote(self, seller: Any) -> None:
        accepts = _offer(seller, "/weather")["accepts"]
        assert len(accepts) == 1
        accepted = accepts[0]
        assert accepted["scheme"] == "exact"
        assert accepted["network"] == "aws:base"
        assert accepted["amount"] == "0.10"
        assert accepted["asset"] == "iso4217:USD"
        assert accepted["payTo"] == "urn:x402:agentic-commerce:see-quote"
        assert accepted["extra"]["quoteToken"].count(".") == 2

    def test_each_402_carries_a_new_quote(self, seller: Any) -> None:
        first = _offer(seller, "/weather")["accepts"][0]["extra"]["quoteToken"]
        second = _offer(seller, "/weather")["accepts"][0]["extra"]["quoteToken"]
        assert first != second


class TestPaidRequest:
    def test_valid_payment_is_served_and_settled(
        self, seller: Any, service: FakePaymentService
    ) -> None:
        accepted = _offer(seller, "/weather")["accepts"][0]
        response = _pay(
            seller, "/weather", accepted, service.issue(accepted["extra"]["quoteToken"])
        )
        assert response.status_code == 200
        settlement = decode_header(response.headers["PAYMENT-RESPONSE"])
        assert settlement["success"] is True
        assert settlement["transaction"].startswith("awsmp-")
        assert settlement["payer"] == "123456789012"

    def test_payment_for_a_cheaper_route_is_rejected(
        self, seller: Any, service: FakePaymentService
    ) -> None:
        cheap = _offer(seller, "/ping")["accepts"][0]
        token = service.issue(cheap["extra"]["quoteToken"])
        assert _pay(seller, "/weather", cheap, token).status_code == 402

    def test_payment_for_another_route_with_relabelled_price_is_rejected(
        self, seller: Any, service: FakePaymentService
    ) -> None:
        cheap = _offer(seller, "/ping")["accepts"][0]
        token = service.issue(cheap["extra"]["quoteToken"])
        relabelled = {**cheap, "amount": "0.10"}
        assert _pay(seller, "/weather", relabelled, token).status_code == 402

    def test_quote_signed_by_another_seller_is_rejected(
        self, seller: Any, service: FakePaymentService
    ) -> None:
        other_seller = fastapi_client(seller_signer("https://other.example.com"))
        foreign = _offer(other_seller, "/weather")["accepts"][0]
        token = service.issue(foreign["extra"]["quoteToken"], audience="https://other.example.com")
        assert _pay(seller, "/weather", foreign, token).status_code == 402

    def test_token_not_issued_by_the_service_is_rejected(
        self, seller: Any, service: FakePaymentService
    ) -> None:
        accepted = _offer(seller, "/weather")["accepts"][0]
        forged = FakePaymentService().issue(accepted["extra"]["quoteToken"])
        assert _pay(seller, "/weather", accepted, forged).status_code == 402

    def test_wrong_issuer_claim_is_rejected(self, seller: Any, service: FakePaymentService) -> None:
        accepted = _offer(seller, "/weather")["accepts"][0]
        token = service.issue(accepted["extra"]["quoteToken"], issuer="someone-else")
        assert _pay(seller, "/weather", accepted, token).status_code == 402

    def test_expired_token_is_rejected(self, seller: Any, service: FakePaymentService) -> None:
        accepted = _offer(seller, "/weather")["accepts"][0]
        token = service.issue(accepted["extra"]["quoteToken"], expires_in=-1)
        assert _pay(seller, "/weather", accepted, token).status_code == 402

    def test_token_for_a_different_quote_is_rejected(
        self, seller: Any, service: FakePaymentService
    ) -> None:
        accepted = _offer(seller, "/weather")["accepts"][0]
        other = _offer(seller, "/weather")["accepts"][0]
        token = service.issue(other["extra"]["quoteToken"])
        assert _pay(seller, "/weather", accepted, token).status_code == 402


class TestDPoP:
    @pytest.fixture
    def buyer_key(self) -> tuple[ec.EllipticCurvePrivateKey, dict[str, str]]:
        return ec_key("buyer")

    def test_bound_token_with_valid_proof_is_served(
        self, seller: Any, service: FakePaymentService, buyer_key: Any
    ) -> None:
        private_key, jwk = buyer_key
        offer = _offer(seller, "/weather")
        accepted = offer["accepts"][0]
        token = service.issue(accepted["extra"]["quoteToken"], dpop_jwk=jwk)
        proof = dpop_proof(
            private_key, jwk, htm="GET", htu=offer["resource"]["url"], access_token=token
        )
        assert _pay(seller, "/weather", accepted, token, DPoP=proof).status_code == 200

    def test_bound_token_without_proof_is_rejected(
        self, seller: Any, service: FakePaymentService, buyer_key: Any
    ) -> None:
        accepted = _offer(seller, "/weather")["accepts"][0]
        token = service.issue(accepted["extra"]["quoteToken"], dpop_jwk=buyer_key[1])
        assert _pay(seller, "/weather", accepted, token).status_code == 402

    def test_proof_from_another_key_is_rejected(
        self, seller: Any, service: FakePaymentService, buyer_key: Any
    ) -> None:
        offer = _offer(seller, "/weather")
        accepted = offer["accepts"][0]
        token = service.issue(accepted["extra"]["quoteToken"], dpop_jwk=buyer_key[1])
        other_key, other_jwk = ec_key("other")
        proof = dpop_proof(
            other_key, other_jwk, htm="GET", htu=offer["resource"]["url"], access_token=token
        )
        assert _pay(seller, "/weather", accepted, token, DPoP=proof).status_code == 402

    def test_proof_for_another_url_is_rejected(
        self, seller: Any, service: FakePaymentService, buyer_key: Any
    ) -> None:
        private_key, jwk = buyer_key
        offer = _offer(seller, "/weather")
        accepted = offer["accepts"][0]
        token = service.issue(accepted["extra"]["quoteToken"], dpop_jwk=jwk)
        other_url = offer["resource"]["url"].replace("/weather", "/ping")
        proof = dpop_proof(private_key, jwk, htm="GET", htu=other_url, access_token=token)
        assert _pay(seller, "/weather", accepted, token, DPoP=proof).status_code == 402

    def test_proof_over_another_token_is_rejected(
        self, seller: Any, service: FakePaymentService, buyer_key: Any
    ) -> None:
        private_key, jwk = buyer_key
        offer = _offer(seller, "/weather")
        accepted = offer["accepts"][0]
        token = service.issue(accepted["extra"]["quoteToken"], dpop_jwk=jwk)
        proof = dpop_proof(
            private_key, jwk, htm="GET", htu=offer["resource"]["url"], access_token="other"
        )
        assert _pay(seller, "/weather", accepted, token, DPoP=proof).status_code == 402


def test_facilitator_runs_without_the_http_layer(service: FakePaymentService) -> None:
    """The facilitator can be used directly (for example as a separate service)."""
    from x402.schemas import PaymentPayload, PaymentRequirements

    from fiat_extension_x402 import ExactAgenticCommerceServerScheme

    signer = seller_signer()
    facilitator = register_exact_agentic_commerce_facilitator(
        x402Facilitator(), verifier=_verifier(signer)
    )
    base = PaymentRequirements(
        scheme="exact",
        network="aws:base",
        asset="iso4217:USD",
        amount="1.00",
        pay_to="seller-1",
        max_timeout_seconds=300,
    )
    requirements = ExactAgenticCommerceServerScheme(signer=signer).enhance_payment_requirements(
        base
    )
    payload = PaymentPayload(
        accepted=requirements,
        payload={"paymentToken": service.issue(requirements.extra["quoteToken"])},
    )
    assert asyncio.run(facilitator.verify(payload, requirements)).is_valid
    supported = facilitator.get_supported()
    assert [(k.scheme, k.network) for k in supported.kinds] == [("exact", "aws:base")]
