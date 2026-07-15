# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Standalone live end-to-end smoke test against a real Agent Pay seller.

A single-file, one-shot check of the full buyer flow against a *live* seller
endpoint and the real Agent Pay service:

1. GET the seller endpoint, expecting HTTP 402 with a signed quote token.
2. Create a payment with Agent Pay (SigV4-signed) via the SDK's ``AgentPayClient``.
3. Retry the seller with the payment token, expecting HTTP 200 + the resource.

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
import uuid
from typing import Any, NoReturn

import httpx
from botocore.credentials import Credentials  # type: ignore[import-untyped]

from fiat_extension_x402 import AgentPayClient
from fiat_extension_x402.schemas import CreateAgentPaymentRequest

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


def _retry_with_payment(
    quote_url: str, payment_token: str, accepted: dict[str, Any]
) -> httpx.Response:
    """Retry the seller with the payment token, trying both seller conventions.

    Sellers accept the payment in one of two shapes, so this tries the proven
    convention first and falls back to the other:

    1. ``Authorization: Bearer <raw payment JWT>`` — what the reference deployed
       seller verifies directly.
    2. ``X-Payment: <base64 of {x402Version, accepted, payload}>`` — what the
       SDK's own resource-server middleware decodes.
    """
    # Attempt 1: raw payment JWT as a Bearer token.
    resp = httpx.get(
        quote_url,
        headers={"Authorization": f"Bearer {payment_token}"},
        timeout=30.0,
    )
    if resp.status_code == 200:
        print("   (accepted via Authorization: Bearer)")
        return resp

    # Attempt 2: base64-encoded x402 payment payload under X-Payment.
    wrapper = {
        "x402Version": 1,
        "accepted": accepted,
        "payload": {"paymentToken": payment_token},
    }
    header = base64.b64encode(json.dumps(wrapper).encode()).decode()
    resp2 = httpx.get(quote_url, headers={"X-Payment": header}, timeout=30.0)
    if resp2.status_code == 200:
        print("   (accepted via X-Payment base64 payload)")
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
    client = AgentPayClient(base_url=AGENT_PAY_BASE_URL, credentials=credentials)

    # Step 1: GET the seller endpoint, expecting a 402 with a quote token.
    print("\n1. Calling seller endpoint (expecting 402)...")
    try:
        res = httpx.get(quote_url, timeout=30.0)
    except httpx.HTTPError as exc:
        _fail(f"Seller endpoint unreachable: {exc}")
    if res.status_code != 402:
        _fail(f"Expected 402 from seller, got {res.status_code}")
    print("   -> Got 402 (Payment Required)")

    accepts = (res.json() or {}).get("accepts") or []
    if not accepts:
        _fail("Seller 402 response carried no 'accepts' offers")
    offer = accepts[0]
    extra = offer.get("extra") or {}
    # Accept either snake_case or camelCase from the seller.
    quote_token = extra.get("quoteToken") or extra.get("quote_token")
    if not quote_token:
        _fail("Seller 402 offer carried no quoteToken")
    print(f"   quote: {offer.get('amount')} {offer.get('asset')}  ({offer.get('network')})")

    # Step 2: create the payment with Agent Pay (SigV4-signed by the SDK).
    print("\n2. Creating payment with Agent Pay...")
    try:
        payment = client.create_payment(
            CreateAgentPaymentRequest(
                quote_token=quote_token,
                client_token=str(uuid.uuid4()),
            )
        )
    except Exception as exc:  # noqa: BLE001 - surface any auth/validation failure
        _fail(f"CreateAgentPayment failed: {exc}")
    print(f"   -> Payment created: {payment.payment_id}")

    # Step 3: retry the seller with the payment token, expecting 200.
    print("\n3. Retrying seller with payment token (expecting 200)...")
    final = _retry_with_payment(quote_url, payment.payment_token, offer)
    if final.status_code != 200:
        _fail(f"Expected 200 after payment, got {final.status_code}: {final.text[:200]}")
    print(f"   -> Success: {final.text[:200]}")

    print("\n✅ Agent Pay e2e smoke test PASSED")
    print(f"   Payment ID: {payment.payment_id}")


if __name__ == "__main__":
    main()
