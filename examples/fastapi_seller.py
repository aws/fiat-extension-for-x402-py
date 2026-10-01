# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A FastAPI seller protected by x402's own middleware.

The seller registers the ``exact`` scheme for AWS Marketplace Agentic Commerce
on an x402 resource server, verifies payments with an in-process facilitator,
and protects ``GET /weather`` with ``x402.http.middleware.fastapi``.

Run (uses a KMS key for quote signing)::

    export SELLER_KMS_KEY_ARN=arn:aws:kms:us-east-1:111122223333:alias/my-quote-key
    export SELLER_SERVICE_URL=https://api.example.com
    export SELLER_PAY_TO=prod-example123
    uvicorn examples.fastapi_seller:app --port 8000
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from x402 import x402Facilitator, x402ResourceServer
from x402.http.middleware.fastapi import payment_middleware
from x402.http.types import PaymentOption, RouteConfig

from fiat_extension_x402 import (
    AgenticCommerceVerifier,
    KmsQuoteSigner,
    KmsQuoteSignerConfig,
    KmsSellerKeyResolver,
    register_exact_agentic_commerce_facilitator,
    register_exact_agentic_commerce_server,
)

KMS_KEY_ARN = os.environ["SELLER_KMS_KEY_ARN"]
REGION = os.environ.get("AWS_REGION", "us-east-1")
SERVICE_URL = os.environ["SELLER_SERVICE_URL"]
PAY_TO = os.environ["SELLER_PAY_TO"]

# Seller: signs a quote token into every 402 and checks DPoP proofs.
signer = KmsQuoteSigner(
    KmsQuoteSignerConfig(key_arn=KMS_KEY_ARN, region=REGION, service_url=SERVICE_URL)
)

# Facilitator: verifies payment tokens, in this process.
verifier = AgenticCommerceVerifier(seller_key_resolver=KmsSellerKeyResolver(KMS_KEY_ARN, REGION))
facilitator = register_exact_agentic_commerce_facilitator(x402Facilitator(), verifier=verifier)
server = register_exact_agentic_commerce_server(x402ResourceServer(facilitator), signer=signer)

routes = {
    "GET /weather": RouteConfig(
        accepts=PaymentOption(scheme="exact", network="aws:base", pay_to=PAY_TO, price="$0.01"),
        description="Current weather",
        mime_type="application/json",
    ),
}

app = FastAPI()


@app.get("/weather")
def weather() -> dict[str, object]:
    return {"city": "Seattle", "temperature_f": 58, "conditions": "cloudy"}


app.middleware("http")(payment_middleware(routes, server))
