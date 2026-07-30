# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for fiat_extension_x402.middleware.flask module."""

from __future__ import annotations

import base64
import json
from typing import Any
from unittest.mock import patch

import pytest
from flask import Flask, Request

from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.middleware.flask import (
    AgentPayMiddlewareConfig,
    AgentPayRouteConfig,
    agent_pay_middleware,
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
) -> AgentPayMiddlewareConfig:
    """Create a test config."""
    return AgentPayMiddlewareConfig(
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


class TestAgentPayMiddlewareValidation:
    def test_empty_networks_raises(self) -> None:
        with pytest.raises(ValidationError, match="networks must be a non-empty array"):
            agent_pay_middleware(
                AgentPayMiddlewareConfig(
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
            agent_pay_middleware(
                AgentPayMiddlewareConfig(
                    agent_pay_base_url="https://pay.aws.amazon.com",
                    agent_pay_id="test-id",
                    signer=MockSigner(),
                    service_url="https://api.example.com",
                    networks=["aws:base"],
                    routes={},
                )
            )

    def test_invalid_route_pattern(self) -> None:
        with pytest.raises(ValidationError, match="Invalid route pattern"):
            agent_pay_middleware(
                AgentPayMiddlewareConfig(
                    agent_pay_base_url="https://pay.aws.amazon.com",
                    agent_pay_id="test-id",
                    signer=MockSigner(),
                    service_url="https://api.example.com",
                    networks=["aws:base"],
                    routes={
                        "GET PUT /api/premium": AgentPayRouteConfig(
                            price=1, network="aws:base", pay_to="x"
                        )
                    },
                )
            )


class TestAgentPayMiddlewareRouteMatching:
    def test_non_protected_route_passes_through(self) -> None:
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/free")
        def free() -> str:
            return "free"

        client = app.test_client()
        resp = client.get("/api/free")
        assert resp.status_code == 200

    def test_protected_route_returns_402_without_payment(self) -> None:
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()
        resp = client.get("/api/premium")
        assert resp.status_code == 402
        data = json.loads(resp.data)
        assert "accepts" in data
        assert resp.headers.get("WWW-Authenticate", "").startswith("x402 ")
        assert "PAYMENT-REQUIRED" in resp.headers

    def test_402_body_is_a_valid_x402_v2_payment_required(self) -> None:
        """The advertised version must match the body's actual shape.

        The requirements carry ``amount`` (v2), not ``maxAmountRequired`` +
        ``resource`` (v1), so the body has to declare v2 — a buyer parses it with
        the model the version names, and x402 core dispatches v1 and v2 through
        separate registries.
        """
        import base64

        from x402.schemas import PaymentRequired

        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        resp = app.test_client().get("/api/premium")
        body = json.loads(resp.data)

        assert body["x402Version"] == 2
        parsed = PaymentRequired.model_validate(body)
        assert parsed.accepts[0].scheme == "agent-pay"
        assert parsed.accepts[0].extra["quoteToken"]

        assert resp.headers["WWW-Authenticate"].startswith("x402 version=2,")
        blob = resp.headers["PAYMENT-REQUIRED"]
        assert json.loads(base64.b64decode(blob))["x402Version"] == 2

    def test_method_mismatch_passes_through(self) -> None:
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.post("/api/premium")
        def premium_post() -> str:
            return "post"

        client = app.test_client()
        resp = client.post("/api/premium")
        assert resp.status_code == 200

    def test_wildcard_route(self) -> None:
        config = _make_config(
            routes={
                "GET /api/*": AgentPayRouteConfig(
                    price=0.10,
                    network="aws:base",
                    pay_to="seller-id",
                ),
            }
        )
        app = Flask(__name__)
        init = agent_pay_middleware(config)
        init(app)

        @app.get("/api/anything")
        def anything() -> str:
            return "anything"

        client = app.test_client()
        resp = client.get("/api/anything")
        assert resp.status_code == 402


class TestAgentPayMiddlewarePaymentVerification:
    def test_valid_payment_passes(self) -> None:
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()

        # Mock the facilitator verify to return valid.
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
        assert "PAYMENT-RESPONSE" in resp.headers

    def test_invalid_payment_returns_402(self) -> None:
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()

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
        data = json.loads(resp.data)
        assert data["error"] == "Payment verification failed"

    def test_missing_accepted_returns_400(self) -> None:
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()
        payment_payload = {"payload": {"paymentToken": "x"}}
        encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

        resp = client.get(
            "/api/premium",
            headers={"Authorization": f"x402 {encoded}"},
        )
        assert resp.status_code == 400

    def test_x_payment_header(self) -> None:
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()
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
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()
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
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()
        resp = client.get("/api/premium", headers={"Authorization": "x402 not-valid-base64!!!"})
        assert resp.status_code == 402  # Treated as no payment.

    def test_malformed_x_payment_header_returns_402(self) -> None:
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()
        resp = client.get("/api/premium", headers={"X-Payment": "not-valid!!!"})
        assert resp.status_code == 402

    def test_malformed_payment_signature_header_returns_402(self) -> None:
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()
        resp = client.get("/api/premium", headers={"payment-signature": "not-valid!!!"})
        assert resp.status_code == 402

    def test_method_less_route_matches_any_method(self) -> None:
        config = _make_config(
            routes={
                "/api/any": AgentPayRouteConfig(
                    price=1.0,
                    network="aws:base",
                    pay_to="seller-id",
                ),
            }
        )
        app = Flask(__name__)
        init = agent_pay_middleware(config)
        init(app)

        @app.get("/api/any")
        def any_get() -> str:
            return "any"

        @app.post("/api/any")
        def any_post() -> str:
            return "any"

        client = app.test_client()
        resp_get = client.get("/api/any")
        assert resp_get.status_code == 402
        resp_post = client.post("/api/any")
        assert resp_post.status_code == 402

    def test_on_payment_verified_hook(self) -> None:
        hook_calls: list[tuple[str, str]] = []

        def on_verified(req: Request, payment: Any) -> None:
            hook_calls.append((req.path, payment.payer))

        config = _make_config()
        config.on_payment_verified = on_verified
        app = Flask(__name__)
        init = agent_pay_middleware(config)
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()
        payment_payload = {
            "accepted": {
                "network": "aws:base",
                "amount": "0.15",
                "asset": "iso4217:USD",
                "extra": {"quoteToken": "qt"},
            },
            "payload": {"paymentToken": "pt", "transactionId": "tx-v"},
        }
        encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

        with patch(
            "fiat_extension_x402.facilitator.client.AgentPayFacilitatorClient.verify"
        ) as mock_verify:
            from fiat_extension_x402.facilitator.types import VerifyResponse

            mock_verify.return_value = VerifyResponse(is_valid=True, payer="buyer-v")
            resp = client.get("/api/premium", headers={"Authorization": f"x402 {encoded}"})

        assert resp.status_code == 200
        assert len(hook_calls) == 1
        assert hook_calls[0] == ("/api/premium", "buyer-v")

    def test_on_payment_settled_hook(self) -> None:
        settled_calls: list[tuple[str, str, str]] = []

        def on_settled(req: Request, payment: Any, tx_id: str) -> None:
            settled_calls.append((req.path, payment.payer, tx_id))

        config = _make_config()
        config.on_payment_settled = on_settled
        app = Flask(__name__)
        init = agent_pay_middleware(config)
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()
        payment_payload = {
            "accepted": {
                "network": "aws:base",
                "amount": "0.15",
                "asset": "iso4217:USD",
                "extra": {"quoteToken": "qt"},
            },
            "payload": {"paymentToken": "pt", "transactionId": "tx-s"},
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
        assert settled_calls[0] == ("/api/premium", "buyer-s", "tx-s")

    def test_on_error_hook(self) -> None:
        from flask import Response as FlaskResponse

        def custom_error(exc: Exception, req: Request) -> FlaskResponse:
            return FlaskResponse(
                json.dumps({"custom": str(exc)}),
                status=503,
                content_type="application/json",
            )

        config = _make_config()
        config.on_error = custom_error
        app = Flask(__name__)
        init = agent_pay_middleware(config)
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()

        # Force an error by sending a payment and making verify throw.
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
        assert json.loads(resp.data)["custom"] == "boom"

    def test_internal_error_without_hook(self) -> None:
        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        client = app.test_client()
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
        data = json.loads(resp.data)
        assert data["error"] == "Internal server error"


class TestRunAsync:
    def test_run_async_from_running_loop(self) -> None:
        """Cover the running-loop branch of _run_async."""
        import asyncio

        from fiat_extension_x402.middleware.flask import _run_async

        async def _inner() -> str:
            return "hello"

        async def _caller() -> str:
            # We are inside a running loop, so _run_async takes the thread path.
            result: str = _run_async(_inner())
            return result

        result = asyncio.run(_caller())
        assert result == "hello"


class TestResourceMetadataShape:
    def test_402_nests_resource_metadata(self) -> None:
        """x402 tooling reads url/description/mimeType from `resource`."""
        from x402.schemas import PaymentRequired

        app = Flask(__name__)
        init = agent_pay_middleware(_make_config())
        init(app)

        @app.get("/api/premium")
        def premium() -> str:
            return "premium"

        body = json.loads(app.test_client().get("/api/premium").data)

        assert "url" not in body, "resource metadata must not be flattened onto the body"
        parsed = PaymentRequired.model_validate(body)
        assert parsed.resource is not None
        assert parsed.resource.url.endswith("/api/premium")
        assert parsed.resource.mime_type == "application/json"
