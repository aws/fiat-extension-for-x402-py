# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for fiat_extension_x402.middleware.fastapi module."""

from __future__ import annotations

import base64
import json
from typing import Any
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.middleware.fastapi import (
    AgentPayFastAPIMiddlewareConfig,
    AgentPayRouteConfig,
    agent_pay_fastapi_middleware,
)


class MockSigner:
    """Mock signer for testing."""

    async def sign_quote(self, payload: dict[str, Any]) -> str:
        return "mock.quote.token"

    def get_public_key(self) -> object:
        return {"kty": "EC", "crv": "P-384"}

    def get_service_url(self) -> str:
        return "https://api.example.com"


def _make_config(
    routes: dict[str, AgentPayRouteConfig] | None = None,
) -> AgentPayFastAPIMiddlewareConfig:
    """Create a test config."""
    return AgentPayFastAPIMiddlewareConfig(
        agent_pay_base_url="https://pay.aws.amazon.com",
        agent_pay_id="test-id",
        signer=MockSigner(),
        service_url="https://api.example.com",
        networks=["aws:base"],
        routes=routes
        or {
            "GET /api/premium": AgentPayRouteConfig(
                price=0.15,
                network="aws:base",
                pay_to="seller-id",
            ),
        },
    )


class TestAgentPayFastAPIMiddlewareValidation:
    def test_empty_networks_raises(self) -> None:
        with pytest.raises(ValidationError, match="networks must be a non-empty array"):
            agent_pay_fastapi_middleware(
                AgentPayFastAPIMiddlewareConfig(
                    agent_pay_base_url="https://pay.aws.amazon.com",
                    agent_pay_id="test-id",
                    signer=MockSigner(),
                    service_url="https://api.example.com",
                    networks=[],
                    routes={"GET /": AgentPayRouteConfig(price=1, network="aws:base", pay_to="x")},
                )
            )

    def test_empty_routes_raises(self) -> None:
        with pytest.raises(ValidationError, match="routes must be a non-empty object"):
            agent_pay_fastapi_middleware(
                AgentPayFastAPIMiddlewareConfig(
                    agent_pay_base_url="https://pay.aws.amazon.com",
                    agent_pay_id="test-id",
                    signer=MockSigner(),
                    service_url="https://api.example.com",
                    networks=["aws:base"],
                    routes={},
                )
            )


class TestAgentPayFastAPIMiddlewareRouting:
    def test_non_protected_route_passes_through(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/free")
        async def free() -> dict[str, str]:
            return {"msg": "free"}

        client = TestClient(app)
        resp = client.get("/api/free")
        assert resp.status_code == 200
        assert resp.json() == {"msg": "free"}

    def test_protected_route_returns_402_without_payment(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        client = TestClient(app)
        resp = client.get("/api/premium")
        assert resp.status_code == 402
        data = resp.json()
        assert "accepts" in data
        assert resp.headers.get("www-authenticate", "").startswith("x402 ")
        assert "payment-required" in resp.headers

    def test_402_body_is_a_valid_x402_v2_payment_required(self) -> None:
        """The advertised version must match the body's actual shape.

        The requirements carry ``amount`` (v2), not ``maxAmountRequired`` +
        ``resource`` (v1), so the body has to declare v2 — a buyer parses it with
        the model the version names, and x402 core dispatches v1 and v2 through
        separate registries.
        """
        from x402.schemas import PaymentRequired

        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        resp = TestClient(app).get("/api/premium")
        body = resp.json()

        assert body["x402Version"] == 2
        # Round-trips through the model the declared version names.
        parsed = PaymentRequired.model_validate(body)
        assert parsed.accepts[0].scheme == "agent-pay"
        assert parsed.accepts[0].extra["quoteToken"]

        # The header advertises the same version as the body.
        assert resp.headers["www-authenticate"].startswith("x402 version=2,")

        # And the base64 blob in the header decodes to that same body.
        blob = resp.headers["payment-required"]
        assert json.loads(base64.b64decode(blob))["x402Version"] == 2

    def test_method_mismatch_passes_through(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.post("/api/premium")
        async def premium_post() -> dict[str, str]:
            return {"msg": "post"}

        client = TestClient(app)
        resp = client.post("/api/premium")
        assert resp.status_code == 200


class TestAgentPayFastAPIMiddlewareRouteCompilation:
    def test_invalid_route_pattern_three_parts(self) -> None:
        with pytest.raises(ValidationError, match="Invalid route pattern"):
            agent_pay_fastapi_middleware(
                AgentPayFastAPIMiddlewareConfig(
                    agent_pay_base_url="https://pay.aws.amazon.com",
                    agent_pay_id="test-id",
                    signer=MockSigner(),
                    service_url="https://api.example.com",
                    networks=["aws:base"],
                    routes={
                        "GET /api extra": AgentPayRouteConfig(
                            price=1, network="aws:base", pay_to="x"
                        )
                    },
                )
            )

    def test_path_only_route_matches_any_method(self) -> None:
        config = _make_config(
            routes={
                "/api/any": AgentPayRouteConfig(
                    price=1.0,
                    network="aws:base",
                    pay_to="seller-id",
                ),
            }
        )
        app = FastAPI()
        init = agent_pay_fastapi_middleware(config)
        init(app)

        @app.get("/api/any")
        async def any_get() -> dict[str, str]:
            return {"msg": "any"}

        @app.post("/api/any")
        async def any_post() -> dict[str, str]:
            return {"msg": "any"}

        client = TestClient(app)
        assert client.get("/api/any").status_code == 402
        assert client.post("/api/any").status_code == 402


class TestAgentPayFastAPIMiddlewareVerification:
    def test_valid_payment_passes(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium(request: Request) -> dict[str, Any]:
            payment = getattr(request.state, "agent_pay_payment", None)
            return {"payer": payment.payer if payment else "none"}

        client = TestClient(app)

        payment_payload = {
            "accepted": {
                "network": "aws:base",
                "amount": "0.15",
                "asset": "iso4217:USD",
                "extra": {"quoteToken": "mock.quote.token"},
            },
            "payload": {
                "paymentToken": "mock.payment.token",
                "transactionId": "tx-123",
            },
        }
        encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

        with patch(
            "fiat_extension_x402.facilitator.client.AgentPayFacilitatorClient.verify"
        ) as mock_verify:
            from fiat_extension_x402.facilitator.types import VerifyResponse

            mock_verify.return_value = VerifyResponse(is_valid=True, payer="buyer-123")
            resp = client.get(
                "/api/premium",
                headers={"Authorization": f"x402 {encoded}"},
            )

        assert resp.status_code == 200
        assert resp.json()["payer"] == "buyer-123"
        assert "payment-response" in resp.headers

    def test_invalid_payment_returns_402(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        client = TestClient(app)

        payment_payload = {
            "accepted": {
                "network": "aws:base",
                "amount": "0.15",
                "asset": "iso4217:USD",
                "extra": {"quoteToken": "bad.token"},
            },
            "payload": {
                "paymentToken": "bad.payment.token",
                "transactionId": "tx-456",
            },
        }
        encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

        with patch(
            "fiat_extension_x402.facilitator.client.AgentPayFacilitatorClient.verify"
        ) as mock_verify:
            from fiat_extension_x402.facilitator.types import VerifyResponse

            mock_verify.return_value = VerifyResponse(
                is_valid=False, invalid_reason="invalid", invalid_message="bad payment"
            )
            resp = client.get(
                "/api/premium",
                headers={"Authorization": f"x402 {encoded}"},
            )

        assert resp.status_code == 402
        data = resp.json()
        assert data["error"] == "Payment verification failed"

    def test_missing_accepted_returns_400(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        client = TestClient(app)
        payment_payload = {"payload": {"paymentToken": "x"}}
        encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

        resp = client.get(
            "/api/premium",
            headers={"Authorization": f"x402 {encoded}"},
        )
        assert resp.status_code == 400

    def test_x_payment_header(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        client = TestClient(app)
        payment_payload = {
            "accepted": {
                "network": "aws:base",
                "amount": "0.15",
                "asset": "iso4217:USD",
                "extra": {"quoteToken": "qt"},
            },
            "payload": {"paymentToken": "pt", "transactionId": "tx"},
        }
        encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

        with patch(
            "fiat_extension_x402.facilitator.client.AgentPayFacilitatorClient.verify"
        ) as mock_verify:
            from fiat_extension_x402.facilitator.types import VerifyResponse

            mock_verify.return_value = VerifyResponse(is_valid=True, payer="buyer")
            resp = client.get("/api/premium", headers={"X-Payment": encoded})

        assert resp.status_code == 200

    def test_payment_signature_header(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        client = TestClient(app)
        payment_payload = {
            "accepted": {
                "network": "aws:base",
                "amount": "0.15",
                "asset": "iso4217:USD",
                "extra": {"quoteToken": "qt"},
            },
            "payload": {"paymentToken": "pt", "transactionId": "tx"},
        }
        encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

        with patch(
            "fiat_extension_x402.facilitator.client.AgentPayFacilitatorClient.verify"
        ) as mock_verify:
            from fiat_extension_x402.facilitator.types import VerifyResponse

            mock_verify.return_value = VerifyResponse(is_valid=True, payer="buyer")
            resp = client.get("/api/premium", headers={"payment-signature": encoded})

        assert resp.status_code == 200

    def test_malformed_auth_header_returns_402(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        client = TestClient(app)
        resp = client.get("/api/premium", headers={"Authorization": "x402 not-valid-base64!!!"})
        assert resp.status_code == 402

    def test_malformed_x_payment_header_returns_402(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        client = TestClient(app)
        resp = client.get("/api/premium", headers={"X-Payment": "not-valid!!!"})
        assert resp.status_code == 402

    def test_malformed_payment_signature_header_returns_402(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        client = TestClient(app)
        resp = client.get("/api/premium", headers={"payment-signature": "not-valid!!!"})
        assert resp.status_code == 402


class TestAgentPayFastAPIMiddlewareHooks:
    def test_on_payment_verified_hook(self) -> None:
        hook_calls: list[tuple[Any, Any]] = []

        async def on_verified(req: Request, payment: Any) -> None:
            hook_calls.append((req.url.path, payment.payer))

        config = _make_config()
        config.on_payment_verified = on_verified
        app = FastAPI()
        init = agent_pay_fastapi_middleware(config)
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "ok"}

        client = TestClient(app)
        payment_payload = {
            "accepted": {
                "network": "aws:base",
                "amount": "0.15",
                "asset": "iso4217:USD",
                "extra": {"quoteToken": "qt"},
            },
            "payload": {"paymentToken": "pt", "transactionId": "tx-1"},
        }
        encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

        with patch(
            "fiat_extension_x402.facilitator.client.AgentPayFacilitatorClient.verify"
        ) as mock_verify:
            from fiat_extension_x402.facilitator.types import VerifyResponse

            mock_verify.return_value = VerifyResponse(is_valid=True, payer="buyer-hook")
            resp = client.get("/api/premium", headers={"Authorization": f"x402 {encoded}"})

        assert resp.status_code == 200
        assert len(hook_calls) == 1
        assert hook_calls[0] == ("/api/premium", "buyer-hook")

    def test_on_payment_settled_hook(self) -> None:
        settled_calls: list[tuple[Any, Any, str]] = []

        async def on_settled(req: Request, payment: Any, tx_id: str) -> None:
            settled_calls.append((req.url.path, payment.payer, tx_id))

        config = _make_config()
        config.on_payment_settled = on_settled
        app = FastAPI()
        init = agent_pay_fastapi_middleware(config)
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "ok"}

        client = TestClient(app)
        payment_payload = {
            "accepted": {
                "network": "aws:base",
                "amount": "0.15",
                "asset": "iso4217:USD",
                "extra": {"quoteToken": "qt"},
            },
            "payload": {"paymentToken": "pt", "transactionId": "tx-settled"},
        }
        encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

        with patch(
            "fiat_extension_x402.facilitator.client.AgentPayFacilitatorClient.verify"
        ) as mock_verify:
            from fiat_extension_x402.facilitator.types import VerifyResponse

            mock_verify.return_value = VerifyResponse(is_valid=True, payer="buyer-s")
            resp = client.get("/api/premium", headers={"Authorization": f"x402 {encoded}"})

        assert resp.status_code == 200
        assert len(settled_calls) == 1
        assert settled_calls[0] == ("/api/premium", "buyer-s", "tx-settled")

    def test_internal_error_without_hook(self) -> None:
        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        client = TestClient(app)
        payment_payload = {
            "accepted": {"network": "aws:base", "amount": "0.15", "extra": {"quoteToken": "x"}},
            "payload": {"paymentToken": "x"},
        }
        encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

        with patch(
            "fiat_extension_x402.facilitator.client.AgentPayFacilitatorClient.verify",
            side_effect=RuntimeError("unexpected"),
        ):
            resp = client.get("/api/premium", headers={"Authorization": f"x402 {encoded}"})

        assert resp.status_code == 500
        data = resp.json()
        assert data["error"] == "Internal server error"

    def test_on_error_hook(self) -> None:
        from fastapi.responses import JSONResponse as FastAPIJSONResponse

        def custom_error(exc: Exception, req: Request) -> FastAPIJSONResponse:
            return FastAPIJSONResponse(
                content={"custom": str(exc)},
                status_code=503,
            )

        config = _make_config()
        config.on_error = custom_error
        app = FastAPI()
        init = agent_pay_fastapi_middleware(config)
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        client = TestClient(app)
        payment_payload = {
            "accepted": {"network": "aws:base", "amount": "0.15", "extra": {"quoteToken": "x"}},
            "payload": {"paymentToken": "x"},
        }
        encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

        with patch(
            "fiat_extension_x402.facilitator.client.AgentPayFacilitatorClient.verify",
            side_effect=RuntimeError("boom"),
        ):
            resp = client.get("/api/premium", headers={"Authorization": f"x402 {encoded}"})

        assert resp.status_code == 503
        assert resp.json()["custom"] == "boom"


class TestResourceMetadataShape:
    def test_402_nests_resource_metadata(self) -> None:
        """x402 tooling reads url/description/mimeType from `resource`."""
        from x402.schemas import PaymentRequired

        app = FastAPI()
        init = agent_pay_fastapi_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        async def premium() -> dict[str, str]:
            return {"msg": "premium"}

        body = TestClient(app).get("/api/premium").json()

        assert "url" not in body, "resource metadata must not be flattened onto the body"
        parsed = PaymentRequired.model_validate(body)
        assert parsed.resource is not None
        assert parsed.resource.url.endswith("/api/premium")
        assert parsed.resource.mime_type == "application/json"
