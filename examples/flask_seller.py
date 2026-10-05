# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A Flask seller protected by x402's own middleware.

Same as ``fastapi_seller.py``, using the synchronous x402 objects that Flask's
middleware requires.

Run::

    export SELLER_KMS_KEY_ARN=arn:aws:kms:us-east-1:111122223333:alias/my-quote-key
    export SELLER_SERVICE_URL=https://api.example.com
    export SELLER_PRODUCT_ID=prod-example123
    flask --app examples.flask_seller run --port 8000
"""

from __future__ import annotations

import os

from flask import Flask
from x402 import x402FacilitatorSync, x402ResourceServerSync
from x402.http.middleware.flask import payment_middleware
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
verifier = AgenticCommerceVerifier(seller_key_resolver=KmsSellerKeyResolver(KMS_KEY_ARN, REGION))
facilitator = register_exact_agentic_commerce_facilitator(x402FacilitatorSync(), verifier=verifier)
server = register_exact_agentic_commerce_server(x402ResourceServerSync(facilitator), signer=signer)

routes = {
    "GET /weather": RouteConfig(
        accepts=PaymentOption(scheme="exact", network="aws:base", pay_to=PRODUCT_ID, price="$0.01"),
        description="Current weather",
        mime_type="application/json",
    ),
}

app = Flask(__name__)


@app.get("/weather")
def weather() -> dict[str, object]:
    return {"city": "Seattle", "temperature_f": 58, "conditions": "cloudy"}


payment_middleware(app, routes, server)
