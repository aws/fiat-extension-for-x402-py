# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Example Flask application protected by Agent Pay x402 middleware.

The middleware returns HTTP 402 with a signed quote token for protected routes,
verifies the payment token a buyer sends back, settles the payment, and only
then lets the request through. After a successful payment, ``g.agent_pay_payment``
carries the payment details.

Configuration is read from the environment so no secrets are hardcoded. Set
these before starting the server (an unset ``AGENTPAY_KMS_KEY_ARN`` runs the app
with payment protection disabled, so the free route still works for a smoke
test)::

    export AGENTPAY_KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789012:key/<key-id>"
    export AGENTPAY_REGION="us-east-1"                 # optional, default us-east-1
    export AGENTPAY_SERVICE_URL="https://api.example.com"
    export AGENTPAY_BASE_URL="https://prod.agentpay.marketplace.aws.dev"  # optional
    export AGENTPAY_ID="my-agent-pay-id"               # optional
    export AGENTPAY_PAY_TO="seller-agent-pay-id"

Run with::

    pip install -e ".[dev,flask]"
    flask --app examples.flask_app run --port 5001

Then::

    curl localhost:5001/api/free       # 200 — no payment required
    curl -i localhost:5001/api/premium # 402 — quote token in the body (when configured)
"""

from __future__ import annotations

import os

from flask import Flask, g, jsonify

from fiat_extension_x402.middleware.flask import (
    AgentPayMiddlewareConfig,
    AgentPayRouteConfig,
    agent_pay_middleware,
)
from fiat_extension_x402.signers import KmsSignerConfig, create_kms_signer

app = Flask(__name__)

# Configuration from the environment (see module docstring).
KMS_KEY_ARN = os.environ.get("AGENTPAY_KMS_KEY_ARN")
REGION = os.environ.get("AGENTPAY_REGION", "us-east-1")
SERVICE_URL = os.environ.get("AGENTPAY_SERVICE_URL", "https://api.example.com")
AGENT_PAY_BASE_URL = os.environ.get(
    "AGENTPAY_BASE_URL", "https://prod.agentpay.marketplace.aws.dev"
)
AGENT_PAY_ID = os.environ.get("AGENTPAY_ID", "my-agent-pay-id")
PAY_TO = os.environ.get("AGENTPAY_PAY_TO", "seller-agent-pay-id")


# Wire up the payment middleware only when a signing key is configured. This
# keeps the example importable and the free route testable without AWS access.
if KMS_KEY_ARN:
    signer = create_kms_signer(
        KmsSignerConfig(
            key_arn=KMS_KEY_ARN,
            region=REGION,
            service_url=SERVICE_URL,
        )
    )

    agent_pay_middleware(
        AgentPayMiddlewareConfig(
            agent_pay_base_url=AGENT_PAY_BASE_URL,
            agent_pay_id=AGENT_PAY_ID,
            signer=signer,
            service_url=SERVICE_URL,
            networks=["aws:base"],
            routes={
                "GET /api/premium": AgentPayRouteConfig(
                    price="0.15",
                    network="aws:base",
                    pay_to=PAY_TO,
                    description="Premium content access",
                ),
                "POST /api/generate": AgentPayRouteConfig(
                    price="0.50",
                    network="aws:base",
                    pay_to=PAY_TO,
                    description="AI content generation",
                    dimensions={"tokens": 1500},
                ),
            },
        )
    )(app)


@app.get("/api/free")
def free_endpoint():  # type: ignore[no-untyped-def]
    """Free endpoint — no payment required."""
    return jsonify({"message": "This content is free!"})


@app.get("/api/premium")
def premium_endpoint():  # type: ignore[no-untyped-def]
    """Premium endpoint — requires Agent Pay payment.

    After successful payment, ``g.agent_pay_payment`` contains payment info.
    """
    payment = getattr(g, "agent_pay_payment", None)
    return jsonify(
        {
            "message": "Premium content",
            "payment": {
                "payer": payment.payer if payment else "unknown",
                "transaction_id": payment.transaction_id if payment else "",
            },
        }
    )


@app.post("/api/generate")
def generate_endpoint():  # type: ignore[no-untyped-def]
    """Generation endpoint — higher cost with dimension tracking."""
    payment = getattr(g, "agent_pay_payment", None)
    return jsonify(
        {
            "generated": "AI-generated content here",
            "payment": {
                "payer": payment.payer if payment else "unknown",
                "transaction_id": payment.transaction_id if payment else "",
            },
        }
    )


if __name__ == "__main__":
    app.run(port=5001, debug=True)
