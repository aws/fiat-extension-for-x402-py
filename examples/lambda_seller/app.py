# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The FastAPI seller from ``fastapi_seller.py``, packaged for AWS Lambda.

Lambda environment:

* ``SELLER_KMS_KEY_ARN``: KMS key (ECC_NIST_P384, SIGN_VERIFY) that signs quotes.
* ``SELLER_SERVICE_URL``: the seller's public URL; the quote token's ``iss``.
* ``SELLER_PRODUCT_ID``: the seller's AWS Marketplace product ID.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI
from mangum import Mangum
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
PRODUCT_ID = os.environ["SELLER_PRODUCT_ID"]

signer = KmsQuoteSigner(
    KmsQuoteSignerConfig(key_arn=KMS_KEY_ARN, region=REGION, service_url=SERVICE_URL)
)
verifier = AgenticCommerceVerifier(
    seller_key_resolver=KmsSellerKeyResolver(KMS_KEY_ARN, REGION),
)
facilitator = register_exact_agentic_commerce_facilitator(x402Facilitator(), verifier=verifier)
server = register_exact_agentic_commerce_server(x402ResourceServer(facilitator), signer=signer)

routes = {
    "GET /weather": RouteConfig(
        accepts=PaymentOption(
            scheme="exact",
            network="aws:base",
            pay_to=PRODUCT_ID,  # signed into the quote as payTo and settlement.product_id
            price="$0.01",
            extra={"description": "Current weather", "reference": "weather-v1"},
        ),
        description="Current weather",
        mime_type="application/json",
    ),
}

app = FastAPI()


@app.get("/")
def health() -> dict[str, str]:
    return {"status": "ok", "paid": "/weather"}


@app.get("/weather")
def weather() -> dict[str, object]:
    return {"city": "Seattle", "temperature_f": 58, "conditions": "cloudy"}


app.middleware("http")(payment_middleware(routes, server))


def _with_raw_path(asgi_app: Any) -> Any:
    """Fill in the ASGI ``raw_path`` that Mangum leaves unset.

    x402's FastAPI middleware reads ``scope["raw_path"]`` (an optional ASGI
    field) and fails when it is ``None``, as it is under Mangum.
    """

    async def wrapped(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http" and not scope.get("raw_path"):
            scope = {**scope, "raw_path": quote(scope["path"]).encode("ascii")}
        await asgi_app(scope, receive, send)

    return wrapped


handler = Mangum(_with_raw_path(app), lifespan="off")
