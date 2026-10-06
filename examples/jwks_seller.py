# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A FastAPI seller that signs quotes with its own key and serves the JWKS.

For sellers who manage their quote-signing key outside AWS KMS. The private key
is a PEM file; the public key is published at ``/.well-known/jwks.json``, the
JWKS URL registered for the listing. The in-process facilitator reads the key
from that URL, as a standalone facilitator would.

Create a key (P-384) and run::

    openssl ecparam -name secp384r1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt \
        -out quote-key.pem
    export SELLER_PRIVATE_KEY_FILE=quote-key.pem
    export SELLER_KEY_ID=quote-key-2026-10
    export SELLER_SERVICE_URL=https://api.example.com
    export SELLER_PRODUCT_ID=prod-example123
    uvicorn examples.jwks_seller:app --port 8000
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from x402 import x402Facilitator, x402ResourceServer
from x402.http.middleware.fastapi import payment_middleware
from x402.http.types import PaymentOption, RouteConfig

from fiat_extension_x402 import (
    AgenticCommerceVerifier,
    JwksSellerKeyResolver,
    LocalQuoteSigner,
    jwks_document,
    register_exact_agentic_commerce_facilitator,
    register_exact_agentic_commerce_server,
)

SERVICE_URL = os.environ["SELLER_SERVICE_URL"]
PRODUCT_ID = os.environ["SELLER_PRODUCT_ID"]

signer = LocalQuoteSigner.from_pem(
    Path(os.environ["SELLER_PRIVATE_KEY_FILE"]).read_bytes(),
    kid=os.environ["SELLER_KEY_ID"],
    service_url=SERVICE_URL,
)

# During a key rotation, list the previous key too: jwks_document(new, old).
JWKS = jwks_document(signer.public_jwk)

verifier = AgenticCommerceVerifier(seller_key_resolver=JwksSellerKeyResolver(SERVICE_URL))
facilitator = register_exact_agentic_commerce_facilitator(x402Facilitator(), verifier=verifier)
server = register_exact_agentic_commerce_server(x402ResourceServer(facilitator), signer=signer)

routes = {
    "GET /weather": RouteConfig(
        accepts=PaymentOption(scheme="exact", network="aws:base", pay_to=PRODUCT_ID, price="$0.01"),
        description="Current weather",
        mime_type="application/json",
    ),
}

app = FastAPI()


@app.get("/.well-known/jwks.json")
def jwks() -> dict[str, list[dict[str, Any]]]:
    # Not in ``routes``, so the payment middleware leaves it public.
    return JWKS


@app.get("/weather")
def weather() -> dict[str, object]:
    return {"city": "Seattle", "temperature_f": 58, "conditions": "cloudy"}


app.middleware("http")(payment_middleware(routes, server))
