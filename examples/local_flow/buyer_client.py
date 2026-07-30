# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Buyer client for the local three-process Agent Pay x402 demo.

Drives the full buyer flow against the local seller service and mock Agent Pay
through the x402 framework path — the Agent Pay scheme registered on an
``x402ClientSync``:

1. GET a protected route -> receive 402 Payment Required.
2. Parse the payment requirements from the ``WWW-Authenticate`` header.
3. ``create_payment_payload`` -> x402 core routes to the Agent Pay scheme, which
   calls CreateAgentPayment (SigV4-signed) and returns a payment token.
4. Retry the route with an ``x402`` Authorization header -> 200 + resource.
5. List payments back from Agent Pay to confirm the record landed.

No AWS account is needed: the SigV4 signer uses throwaway local credentials, and
the mock Agent Pay accepts any ``AWS4-HMAC-SHA256`` request.

Run it (with the mock on 3001 and the seller on 3002 already running)::

    python examples/local_flow/buyer_client.py
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import httpx
from botocore.credentials import Credentials  # type: ignore[import-untyped]
from x402.schemas import PaymentRequired

from fiat_extension_x402 import (
    AgentPayClientBuilder,
    AgentPayClientOptions,
    create_agent_pay_client,
)

SERVICE_URL = "http://localhost:3002"
AGENT_PAY_BASE_URL = "http://localhost:3001"

# Throwaway local credentials. The mock Agent Pay only checks for the presence of
# an AWS4-HMAC-SHA256 Authorization header, which SigV4 signing produces.
_CREDENTIALS = Credentials("LOCALDEMOACCESSKEY", "localdemosecretkey")


def _parse_402(www_authenticate: str) -> dict[str, Any]:
    """Extract and decode the base64 ``accepts`` blob from a WWW-Authenticate header."""
    match = re.search(r'accepts="([^"]+)"', www_authenticate)
    if not match:
        raise RuntimeError("No accepts= blob in WWW-Authenticate header")
    return json.loads(base64.b64decode(match.group(1)))  # type: ignore[no-any-return]


def _pay_and_fetch(buyer: AgentPayClientBuilder, path: str) -> None:
    """Run the 402 -> pay -> retry flow for a single protected route."""
    print(f"\n── GET {path} ───────────────────────────────")

    # Step 1: unpaid request -> 402.
    resp = httpx.get(f"{SERVICE_URL}{path}")
    print(f"  [buyer] first GET -> {resp.status_code} {resp.reason_phrase}")
    if resp.status_code != 402:
        raise RuntimeError(f"expected 402, got {resp.status_code}")

    # Step 2: parse the 402 body into the x402 PaymentRequired model.
    body = _parse_402(resp.headers["WWW-Authenticate"])
    payment_required = PaymentRequired.model_validate(body)
    offer = payment_required.accepts[0]
    print(f"  [buyer] quote: {offer.amount} {offer.asset}")

    # Step 3: x402 core selects the agent-pay offer and dispatches to the Agent
    # Pay scheme, which calls CreateAgentPayment (SigV4-signed) for us.
    payload = buyer.create_payment_payload(payment_required)
    print(f"  [buyer] created payment {payload.payload['paymentId']}")

    # Step 4: retry with the x402 Authorization header this demo's seller expects.
    #
    # This demo predates the standard header names, so it carries the payload
    # under `Authorization: x402 <base64>`. A seller reading the standard
    # PAYMENT-SIGNATURE header would instead let core do the encoding:
    #
    #     x402HTTPClientSync(buyer.client).encode_payment_signature_header(payload)
    x_payment = payload.model_dump(by_alias=True, exclude_none=True)
    header = "x402 " + base64.b64encode(json.dumps(x_payment).encode()).decode()
    paid = httpx.get(f"{SERVICE_URL}{path}", headers={"Authorization": header})
    print(f"  [buyer] paid GET  -> {paid.status_code} {paid.reason_phrase}")
    paid.raise_for_status()

    data = paid.json()
    print(f"  [buyer] resource: {data['message']}  (paidBy={data['data']['paidBy']})")
    print(f"          content:  {data['data']['content']}")


def main() -> None:
    """Run the buyer flow against both protected routes, then list payments."""
    print("🧪  Agent Pay x402 — local buyer flow")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    buyer = create_agent_pay_client(
        AgentPayClientOptions(
            agent_pay_id="local-demo-buyer",
            agent_pay_base_url=AGENT_PAY_BASE_URL,
            credentials=_CREDENTIALS,
        )
    )
    buyer.register_network("aws:base")

    _pay_and_fetch(buyer, "/foo")
    _pay_and_fetch(buyer, "/bar")

    # Confirm the payments are queryable back from Agent Pay. Get/List are on the
    # transport client, reachable through the builder.
    print("\n── ListAgentPayments ───────────────────────")
    listed = buyer.agent_pay_client.list_payments()
    print(f"  [buyer] {len(listed.payments)} payment(s) on record:")
    for summary in listed.payments:
        print(f"          {summary.payment_id}  product={summary.product_id}")

    print("\n✅  All done — payments created, verified, and served.")


if __name__ == "__main__":
    main()
