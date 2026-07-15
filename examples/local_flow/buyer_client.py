# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Buyer client for the local three-process Agent Pay x402 demo.

Drives the full buyer flow against the local seller service and mock Agent Pay,
using the SDK's real :class:`AgentPayClient`:

1. GET a protected route -> receive 402 Payment Required.
2. Parse the signed quote token from the ``WWW-Authenticate`` header.
3. ``create_payment`` against Agent Pay (SigV4-signed) -> payment token.
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
import uuid
from typing import Any

import httpx
from botocore.credentials import Credentials  # type: ignore[import-untyped]

from fiat_extension_x402 import AgentPayClient
from fiat_extension_x402.schemas import CreateAgentPaymentRequest

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


def _pay_and_fetch(client: AgentPayClient, path: str) -> None:
    """Run the 402 -> pay -> retry flow for a single protected route."""
    print(f"\n── GET {path} ───────────────────────────────")

    # Step 1: unpaid request -> 402.
    resp = httpx.get(f"{SERVICE_URL}{path}")
    print(f"  [buyer] first GET -> {resp.status_code} {resp.reason_phrase}")
    if resp.status_code != 402:
        raise RuntimeError(f"expected 402, got {resp.status_code}")

    # Step 2: parse the payment requirements + quote token from the 402.
    payment_required = _parse_402(resp.headers["WWW-Authenticate"])
    requirements = payment_required["accepts"][0]
    quote_token = requirements["extra"]["quoteToken"]
    print(f"  [buyer] quote: {requirements['amount']} {requirements['asset']}")

    # Step 3: create the payment with Agent Pay (SigV4-signed by AgentPayClient).
    created = client.create_payment(
        CreateAgentPaymentRequest(
            quote_token=quote_token,
            client_token=str(uuid.uuid4()),
        )
    )
    print(f"  [buyer] created payment {created.payment_id}")

    # Step 4: retry with the x402 Authorization header.
    x_payment = {
        "x402Version": 1,
        "accepted": requirements,
        "payload": {
            "paymentToken": created.payment_token,
            "paymentId": created.payment_id,
        },
    }
    header = "x402 " + base64.b64encode(json.dumps(x_payment).encode()).decode()
    paid = httpx.get(f"{SERVICE_URL}{path}", headers={"Authorization": header})
    print(f"  [buyer] paid GET  -> {paid.status_code} {paid.reason_phrase}")
    paid.raise_for_status()

    data = paid.json()
    print(f"  [buyer] resource: {data['message']}  (paidBy={data['data']['paidBy']})")
    print(f"          secret:   {data['data']['secret']}")


def main() -> None:
    """Run the buyer flow against both protected routes, then list payments."""
    print("🧪  Agent Pay x402 — local buyer flow")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    client = AgentPayClient(
        base_url=AGENT_PAY_BASE_URL,
        credentials=_CREDENTIALS,
    )

    _pay_and_fetch(client, "/foo")
    _pay_and_fetch(client, "/bar")

    # Confirm the payments are queryable back from Agent Pay.
    print("\n── ListAgentPayments ───────────────────────")
    listed = client.list_payments()
    print(f"  [buyer] {len(listed.payments)} payment(s) on record:")
    for summary in listed.payments:
        print(f"          {summary.payment_id}  product={summary.product_id}")

    print("\n✅  All done — payments created, verified, and served.")


if __name__ == "__main__":
    main()
