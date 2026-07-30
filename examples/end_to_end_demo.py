# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Self-contained end-to-end Agent Pay x402 demo — no network, no credentials.

This script runs the complete payment round-trip entirely in-process:

1. **Seller** builds an HTTP 402 response with a signed quote token
   (``enhance_payment_requirements`` + a local service signer).
2. **Agent Pay** (mocked here) issues a payment token JWT that embeds the
   quote, signed with its own key.
3. **Buyer** wraps the payment token into an x402 ``X-Payment`` payload and
   retries the request.
4. **Seller** verifies the payment token against the (in-memory) Agent Pay and
   seller JWKS endpoints (``AgentPayFacilitatorClient.verify``) and settles.

Everything that touches the wire — the Agent Pay and seller JWKS endpoints — is
served from in-memory mocks via ``respx``, so this runs anywhere with no AWS
account, KMS key, or live service. It is the runnable companion to the
in-process integration tests under ``tests/integration``.

Run it::

    python examples/end_to_end_demo.py

``respx`` ships with the package's ``dev`` extra (``pip install -e ".[dev]"``).
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from typing import Any

import httpx
import jwt as pyjwt
import respx
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP384R1,
    EllipticCurvePrivateKey,
    generate_private_key,
)

from fiat_extension_x402 import (
    AgentPayFacilitatorClient,
    enhance_payment_requirements,
    to_service_agent_pay_signer,
)
from fiat_extension_x402.constants import AGENT_PAY_JWKS_BASE_URL, WELL_KNOWN_JWKS_PATH

# The seller's public identity. It is the ``iss`` of every quote token, and the
# SDK discovers the seller's public key at ``{SERVICE_URL}/.well-known/jwks.json``.
SERVICE_URL = "https://api.example-seller.com"

# The Agent Pay provider's issuer (the ``iss`` of payment tokens).
AGENT_PAY_ISSUER = "awsmp-agentpay.amazonaws.com"

# Where each party publishes its public keys. The facilitator fetches the Agent
# Pay keys from the production CDN base URL by default; the seller keys live at
# the seller's own service URL.
AGENT_PAY_JWKS_URL = f"{AGENT_PAY_JWKS_BASE_URL.rstrip('/')}{WELL_KNOWN_JWKS_PATH}"
SELLER_JWKS_URL = f"{SERVICE_URL}{WELL_KNOWN_JWKS_PATH}"


def _b64url(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_es384_keypair(kid: str) -> tuple[EllipticCurvePrivateKey, dict[str, Any]]:
    """Generate an ES384 (P-384) key pair and its public JWK with the given kid."""
    private_key = generate_private_key(SECP384R1())
    numbers = private_key.public_key().public_numbers()
    public_jwk: dict[str, Any] = {
        "kty": "EC",
        "crv": "P-384",
        "x": _b64url(numbers.x.to_bytes(48, "big")),
        "y": _b64url(numbers.y.to_bytes(48, "big")),
        "kid": kid,
        "use": "sig",
        "alg": "ES384",
    }
    return private_key, public_jwk


def issue_payment_token(
    agent_pay_key: EllipticCurvePrivateKey,
    agent_pay_jwk: dict[str, Any],
    quote_token: str,
    *,
    buyer: str,
) -> str:
    """Stand in for the Agent Pay service: mint a payment token embedding the quote.

    In production this JWT is returned by ``POST /CreateAgentPayment`` and signed
    by Agent Pay's private key. Here we sign it locally so the demo needs no
    network.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": AGENT_PAY_ISSUER,
        "aud": SERVICE_URL,
        "iat": now,
        "exp": now + 3600,
        "sub": buyer,
        "payment_id": f"awsmp-{uuid.uuid4()}",
        "quote_token": quote_token,
    }
    return pyjwt.encode(
        claims,
        agent_pay_key,
        algorithm="ES384",
        headers={"kid": agent_pay_jwk["kid"]},
    )


async def main() -> None:
    """Run the full seller -> Agent Pay -> buyer -> verify round-trip."""
    print("=== Agent Pay x402 — in-process end-to-end demo ===\n")

    # --- Key setup (seller + Agent Pay each own a signing key) -----------------
    seller_key, seller_jwk = make_es384_keypair("seller-key-1")
    agent_pay_key, agent_pay_jwk = make_es384_keypair("agentpay-key-1")

    # The seller signs quote tokens with a local in-process signer. In production
    # this would be a KMS-backed signer (see create_kms_signer / the README).
    seller_signer = to_service_agent_pay_signer(seller_key, seller_jwk, SERVICE_URL)

    # --- Step 1: Seller returns HTTP 402 with a signed quote -------------------
    base_requirements: dict[str, Any] = {
        "scheme": "agent-pay",
        "network": "aws:base",
        "payTo": "seller-agent-pay-id",
        "amount": "0.15",
        "asset": "iso4217:USD",
        "maxTimeoutSeconds": 300,
        "extra": {"description": "Premium API access"},
    }
    requirements = await enhance_payment_requirements(base_requirements, seller_signer)
    quote_token = requirements["extra"]["quoteToken"]
    print("[seller] 402 Payment Required")
    print(f"         amount       = {requirements['amount']} {requirements['asset']}")
    print(f"         payTo        = {requirements['payTo']}  (sentinel; quote is authoritative)")
    print(f"         quote token  = {quote_token[:48]}...\n")

    # --- Step 2: Agent Pay authorizes the payment (mocked) ---------------------
    # The buyer would POST the quote token to Agent Pay; we mint the response.
    buyer = "buyer-account-123"
    payment_token = issue_payment_token(agent_pay_key, agent_pay_jwk, quote_token, buyer=buyer)
    payment_id = pyjwt.decode(payment_token, options={"verify_signature": False})["payment_id"]
    print("[agent-pay] CreateAgentPayment ->")
    print(f"            paymentId    = {payment_id}")
    print(f"            paymentToken = {payment_token[:48]}...\n")

    # --- Step 3: Buyer retries with the X-Payment header -----------------------
    # The buyer packages the payment token into an x402 payload and base64-encodes
    # it into the X-Payment header. The seller middleware decodes this same shape.
    x_payment = {
        "x402Version": 2,
        "accepted": requirements,
        "payload": {"paymentToken": payment_token, "paymentId": payment_id},
    }
    x_payment_header = base64.b64encode(json.dumps(x_payment).encode()).decode()
    print("[buyer] retry GET /resource")
    print(f"        X-Payment    = {x_payment_header[:48]}...\n")

    # --- Step 4: Seller verifies the payment token + settles -------------------
    # The facilitator needs the Agent Pay and seller JWKS to be reachable. We
    # serve both from in-memory mocks so no real HTTP happens.
    with respx.mock:
        respx.get(AGENT_PAY_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [agent_pay_jwk]})
        )
        respx.get(SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [seller_jwk]})
        )

        facilitator = AgentPayFacilitatorClient()
        verify_requirements = {
            "amount": requirements["amount"],
            "asset": requirements["asset"],
            "network": requirements["network"],
        }
        result = facilitator.verify(payment_token, quote_token, verify_requirements)

        print("[seller] verify ->")
        print(f"         is_valid     = {result.is_valid}")
        print(f"         payer        = {result.payer}")
        if not result.is_valid:
            print(f"         reason       = {result.invalid_reason}: {result.invalid_message}")
            raise SystemExit(1)

        settle = facilitator.settle(payment_id=payment_id, network="aws:base")
        print("\n[seller] settle (auto-captured by Agent Pay) ->")
        print(f"         success      = {settle.success}")
        print(f"         transaction  = {settle.transaction}\n")

    print("=== 200 OK — resource delivered to the buyer ===")


if __name__ == "__main__":
    asyncio.run(main())
