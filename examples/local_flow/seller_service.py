# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Seller resource service protected by Agent Pay x402 (local three-process demo).

A Flask service with two paid routes. For an unpaid request it returns HTTP 402
with a signed quote token; for a paid request it verifies the buyer's payment
token through the Agent Pay facilitator and serves the protected resource.

This wires the SDK's :class:`AgentPayResourceServer` directly rather than the
plug-in middleware, because the demo points verification at the *local* mock
Agent Pay (port 3001). The facilitator's ``jwks_base_url`` is overridden to the
mock so payment tokens verify against the mock's published key; the seller signs
its own quote tokens with a local ES384 key and serves them at its JWKS
endpoint, which the facilitator fetches to verify the embedded quote.

Run it (port 3002), with the mock Agent Pay already running on 3001::

    python examples/local_flow/seller_service.py
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1, generate_private_key
from flask import Flask, Response, jsonify, request

from fiat_extension_x402.builders.resource_server_builder import (
    AgentPayResourceServerOptions,
    InitializeOptions,
    create_agent_pay_resource_server,
)
from fiat_extension_x402.facilitator import AgentPayFacilitatorClient
from fiat_extension_x402.signers import to_service_agent_pay_signer

PORT = 3002
SERVICE_URL = f"http://localhost:{PORT}"
AGENT_PAY_BASE_URL = "http://localhost:3001"
KID = "seller-key-1"

# Paid routes: path -> (price, description). Both on the aws:base network.
ROUTES: dict[str, dict[str, Any]] = {
    "/foo": {"price": "0.15", "description": "Access to /foo"},
    "/bar": {"price": "1.00", "description": "Access to /bar"},
}

app = Flask(__name__)


def _b64url(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --- Seller quote-signing key (ES384) ----------------------------------------
_seller_key = generate_private_key(SECP384R1())
_numbers = _seller_key.public_key().public_numbers()
SELLER_JWK: dict[str, Any] = {
    "kty": "EC",
    "crv": "P-384",
    "x": _b64url(_numbers.x.to_bytes(48, "big")),
    "y": _b64url(_numbers.y.to_bytes(48, "big")),
    "kid": KID,
    "use": "sig",
    "alg": "ES384",
}

# Build the resource server with a local signer, then point its facilitator at
# the mock Agent Pay so payment tokens verify against the mock's JWKS.
_signer = to_service_agent_pay_signer(_seller_key, SELLER_JWK, SERVICE_URL)
_server = create_agent_pay_resource_server(
    AgentPayResourceServerOptions(
        agent_pay_base_url=AGENT_PAY_BASE_URL,
        agent_pay_id="mock-agent-pay-provider",
        signer=_signer,
        service_url=SERVICE_URL,
    )
)
_server.register_network("aws:base")
_server.initialize(InitializeOptions(disable_default_fallback=True))
# Override the facilitator to fetch Agent Pay's keys from the local mock.
_server._facilitator = AgentPayFacilitatorClient(jwks_base_url=AGENT_PAY_BASE_URL)


def _payment_required(path: str, cfg: dict[str, Any]) -> Response:
    """Build a 402 response carrying a signed quote token."""
    requirements = asyncio.run(
        _server.build_payment_requirements(
            network="aws:base",
            pay_to="seller-pay-789",
            price=cfg["price"],
            extra={"description": cfg["description"]},
        )
    )
    payment_required = {
        "x402Version": 2,
        "accepts": [requirements],
        "url": f"{SERVICE_URL}{path}",
        "description": cfg["description"],
        "mimeType": "application/json",
    }
    accepts_b64 = base64.b64encode(json.dumps(payment_required).encode()).decode()
    resp = jsonify(
        {
            "error": "Payment Required",
            "message": f"This endpoint requires payment (${cfg['price']})",
        }
    )
    resp.status_code = 402
    resp.headers["WWW-Authenticate"] = f'x402 version=2, accepts="{accepts_b64}"'
    return resp


def _handle(path: str) -> Response:
    """Shared handler: 402 when unpaid, verified resource when paid."""
    cfg = ROUTES[path]

    # Payment arrives in the x402 Authorization header: "x402 <base64-json>".
    auth = request.headers.get("authorization", "")
    if not auth.startswith("x402 "):
        print(f"  [seller] 402 for {path} (no payment)")
        return _payment_required(path, cfg)

    try:
        payload = json.loads(base64.b64decode(auth[5:]))
    except Exception:  # noqa: BLE001 - malformed header
        return _send_error(400, "Invalid X-Payment payload")

    accepted = payload.get("accepted")
    if not accepted:
        return _send_error(400, "Payment missing accepted requirements")

    expected_quote = accepted.get("extra", {}).get("quoteToken", "")
    payment_token = payload.get("payload", {}).get("paymentToken", "")

    result = _server.facilitator.verify(payment_token, expected_quote, accepted)
    if not result.is_valid:
        print(f"  [seller] verify FAILED for {path}: {result.invalid_message}")
        return _send_error(402, f"Payment verification failed: {result.invalid_message}")

    print(f"  [seller] verified {path}  payer={result.payer}")
    return jsonify(
        {
            "message": f"Hello from {path}!",
            "data": {
                "content": f"This is protected content at {path}",
                "paidBy": result.payer,
            },
        }
    )


@app.get("/foo")
def foo() -> Response:
    """Protected route ($0.15)."""
    return _handle("/foo")


@app.get("/bar")
def bar() -> Response:
    """Protected route ($1.00)."""
    return _handle("/bar")


@app.get("/.well-known/jwks.json")
def jwks() -> Response:
    """Publish the seller's quote-signing public key."""
    return jsonify({"keys": [SELLER_JWK]})


@app.get("/health")
def health() -> Response:
    """Liveness probe (no payment required)."""
    return jsonify({"status": "healthy", "service": "seller-service"})


def _send_error(status: int, message: str) -> Response:
    resp = jsonify({"error": message})
    resp.status_code = status
    return resp


if __name__ == "__main__":
    print("")
    print("🔒  Seller service (Agent Pay x402 protected)")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"   Service URL:  {SERVICE_URL}")
    print(f"   Agent Pay:    {AGENT_PAY_BASE_URL}")
    print("   GET /foo  ($0.15)   GET /bar  ($1.00)   [aws:base]")
    print("   GET /health         GET /.well-known/jwks.json")
    print(
        "   ⚠️  Start the mock Agent Pay first: python examples/local_flow/mock_agent_pay_server.py"
    )
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    app.run(port=PORT)
