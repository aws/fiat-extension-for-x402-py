# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Standalone live end-to-end smoke test against a real Agent Pay seller.

A single-file, one-shot check of the full buyer flow against a *live* seller
endpoint and the real Agent Pay service:

1. GET the seller endpoint, expecting HTTP 402 with a signed quote token.
2. Create a payment through x402 core: the Agent Pay scheme is registered for the
   network the seller quoted, and ``create_payment_payload`` routes the offer to
   it, which calls CreateAgentPayment (SigV4-signed).
3. Retry the seller with the payment attached, expecting HTTP 200 + the resource.

Unlike the pytest suite under ``tests/e2e/`` (run with ``pytest -m e2e``), this is
a plain script you can hand to anyone to confirm a deployed endpoint works. It
uses only the SDK plus its runtime dependencies — no dev extras.

Configuration (via environment, no secrets hardcoded):

* ``AGENTPAY_QUOTE_URL``  — required. The seller endpoint that returns a 402 with
  a signed quote token (its ``iss``).
* ``AGENTPAY_BASE_URL``   — optional. Agent Pay service base URL. Defaults to the
  production endpoint.
* ``AGENTPAY_REGION``     — optional. SigV4 signing region. Defaults to ``us-east-1``.

Buyer AWS credentials are read from the ambient environment (profile or
``AWS_*`` variables), so an AWS identity must be active.

Run it::

    AGENTPAY_QUOTE_URL="https://<seller-endpoint>/" python examples/live_e2e_smoke.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
from typing import Any, NoReturn

import httpx
from botocore.credentials import Credentials  # type: ignore[import-untyped]
from x402.schemas import PaymentRequired, PaymentRequiredV1

from fiat_extension_x402 import AgentPayClientOptions, create_agent_pay_client
from fiat_extension_x402.constants import DEFAULT_NETWORK

AGENT_PAY_BASE_URL = os.environ.get(
    "AGENTPAY_BASE_URL", "https://prod.agentpay.marketplace.aws.dev"
)
REGION = os.environ.get("AGENTPAY_REGION", "us-east-1")


def _fail(message: str) -> NoReturn:
    """Print a failure line and exit non-zero."""
    print(f"\n❌ FAILED: {message}")
    sys.exit(1)


def _resolve_buyer_credentials() -> Credentials:
    """Resolve ambient AWS credentials (profile or AWS_* env) for SigV4 signing."""
    import botocore.session  # type: ignore[import-untyped]

    resolved = botocore.session.Session().get_credentials()
    if resolved is None:
        _fail(
            "No AWS credentials found. Activate an AWS profile or set "
            "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN)."
        )
    frozen = resolved.get_frozen_credentials()
    return Credentials(
        access_key=frozen.access_key,
        secret_key=frozen.secret_key,
        token=getattr(frozen, "token", None),
    )


def _select_agent_pay_offer(body: dict[str, Any]) -> dict[str, Any]:
    """Pick the ``agent-pay`` offer on an ``aws:*`` network from a 402 body.

    A seller's 402 can advertise multiple payment options in ``accepts``
    (different schemes/networks), so never assume ``accepts[0]`` is Agent Pay.
    """
    accepts = body.get("accepts") or []
    if not accepts:
        _fail("Seller 402 response carried no 'accepts' offers")
    offer = next(
        (
            o
            for o in accepts
            if o.get("scheme") == "agent-pay" and str(o.get("network", "")).startswith("aws:")
        ),
        None,
    )
    if offer is None:
        schemes = [f"{o.get('scheme')}/{o.get('network')}" for o in accepts]
        _fail(f"402 response contains no agent-pay (aws) payment option; offered: {schemes}")
    return offer


def _as_payment_required(
    body: dict[str, Any], x402_version: int
) -> PaymentRequired | PaymentRequiredV1:
    """Parse a seller's 402 body into the matching x402 model.

    Sellers in the wild emit either version — this SDK's own FastAPI/Flask
    middleware still advertises ``x402Version: 1`` — and x402 core keeps separate
    v1/v2 dispatch paths, so the model has to match what the seller sent.
    """
    if x402_version == 1:
        return PaymentRequiredV1.model_validate(body)
    return PaymentRequired.model_validate(body)


def _retry_with_payment(
    quote_url: str,
    payment_id: str,
    payment_token: str,
    offer: dict[str, Any],
    x402_version: int,
) -> httpx.Response:
    """Retry the seller with the payment attached, standard convention first.

    1. The base64-encoded x402 payment payload, sent under BOTH
       ``PAYMENT-SIGNATURE`` (x402 v2, preferred) and ``X-PAYMENT`` (v1
       fallback). Correctly configured sellers — including this SDK's own
       FastAPI/Flask middleware — decode these headers.
    2. ``Authorization: Bearer <raw payment JWT>`` — fallback only. A seller
       that accepts *only* Bearer is misconfigured (it never decodes the
       standard headers); the fallback keeps the smoke test useful against
       such endpoints while flagging the problem.
    """
    payment_payload = {
        "x402Version": x402_version,
        "accepted": offer,
        "payload": {"paymentToken": payment_token, "paymentId": payment_id},
    }
    encoded = base64.b64encode(json.dumps(payment_payload).encode()).decode()

    # Attempt 1: the standard encoded convention (both header names).
    resp = httpx.get(
        quote_url,
        headers={"PAYMENT-SIGNATURE": encoded, "X-PAYMENT": encoded},
        timeout=30.0,
    )
    if resp.status_code == 200:
        print("   (accepted via encoded PAYMENT-SIGNATURE/X-PAYMENT — standard convention)")
        return resp

    # Attempt 2: raw payment JWT as a Bearer token (misconfigured-seller fallback).
    resp2 = httpx.get(
        quote_url,
        headers={"Authorization": f"Bearer {payment_token}"},
        timeout=30.0,
    )
    if resp2.status_code == 200:
        print(
            "   ⚠️  Seller accepted only 'Authorization: Bearer' and re-402'd the standard\n"
            "       encoded PAYMENT-SIGNATURE/X-PAYMENT headers. That endpoint is\n"
            "       misconfigured — report it to the seller."
        )
    return resp2


def main() -> None:
    """Run the live 402 -> pay -> retry -> 200 smoke flow."""
    quote_url = os.environ.get("AGENTPAY_QUOTE_URL")
    if not quote_url:
        _fail("Set AGENTPAY_QUOTE_URL to the seller endpoint (returns HTTP 402).")

    print("🧪  Agent Pay live e2e smoke test")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"   Seller:    {quote_url}")
    print(f"   Agent Pay: {AGENT_PAY_BASE_URL}")

    credentials = _resolve_buyer_credentials()
    # The Agent Pay scheme registered on an x402 client: create_payment_payload
    # below goes through x402 core, which routes the offer to this scheme.
    buyer = create_agent_pay_client(
        AgentPayClientOptions(
            agent_pay_id="agentpay-live-smoke",
            agent_pay_base_url=AGENT_PAY_BASE_URL,
            credentials=credentials,
        )
    )

    # Step 1: GET the seller endpoint, expecting a 402 with a quote token.
    print("\n1. Calling seller endpoint (expecting 402)...")
    try:
        res = httpx.get(quote_url, timeout=30.0)
    except httpx.HTTPError as exc:
        _fail(f"Seller endpoint unreachable: {exc}")
    if res.status_code != 402:
        _fail(f"Expected 402 from seller, got {res.status_code}")
    print("   -> Got 402 (Payment Required)")

    body = res.json() or {}
    offer = _select_agent_pay_offer(body)
    extra = offer.get("extra") or {}
    # Accept either snake_case or camelCase from the seller.
    quote_token = extra.get("quoteToken") or extra.get("quote_token")
    if not quote_token:
        _fail("Seller 402 offer carried no quoteToken")
    print(f"   quote: {offer.get('amount')} {offer.get('asset')}  ({offer.get('network')})")

    # Register whatever network this seller quoted, so core can route the offer.
    network = offer.get("network") or DEFAULT_NETWORK
    buyer.register_network(str(network))

    # Step 2: create the payment through x402 core (SigV4-signed by the SDK).
    print("\n2. Creating payment with Agent Pay...")
    x402_version = int(body.get("x402Version") or 1)
    try:
        payload = buyer.create_payment_payload(_as_payment_required(body, x402_version))
    except Exception as exc:  # noqa: BLE001 - surface any auth/validation failure
        _fail(f"create_payment_payload failed: {exc}")
    payment_id = str(payload.payload["paymentId"])
    payment_token = str(payload.payload["paymentToken"])
    print(f"   -> Payment created: {payment_id}")

    # Step 3: retry the seller with the payment attached, expecting 200.
    print("\n3. Retrying seller with payment (expecting 200)...")
    final = _retry_with_payment(
        quote_url,
        payment_id,
        payment_token,
        offer,
        x402_version,
    )
    if final.status_code != 200:
        _fail(f"Expected 200 after payment, got {final.status_code}: {final.text[:200]}")
    print(f"   -> Success: {final.text[:200]}")

    print("\n✅ Agent Pay e2e smoke test PASSED")
    print(f"   Payment ID: {payment_id}")


if __name__ == "__main__":
    main()
