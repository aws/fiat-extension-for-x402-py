# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Mock AWS Marketplace Agent Pay Service for the local three-process demo.

Stands in for the real Agent Pay provider so the seller service and buyer
client can run end to end on localhost with no AWS account. It implements the
Agent Pay HTTP surface the SDK talks to:

    POST /CreateAgentPayment           - mint a signed payment token
    GET  /GetAgentPayment/{paymentId}  - fetch a stored payment
    POST /ListAgentPayments            - list payments for the caller
    GET  /.well-known/jwks.json        - publish the payment-signing public key

Payment tokens are signed with an ES384 key generated at startup; the seller's
facilitator verifies them against the published JWKS. Authentication is the
real Agent Pay shape (AWS SigV4) but validated loosely here: any request with an
``AWS4-HMAC-SHA256`` ``Authorization`` header is accepted, mapping to a fixed
12-digit buyer account id, which is all the SDK's SigV4 client sends.

Run it (port 3001)::

    python examples/local_flow/mock_agent_pay_server.py
"""

from __future__ import annotations

import base64
import time
import uuid
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1, generate_private_key
from flask import Flask, Response, jsonify, request

PORT = 3001
ISSUER = "awsmp-agentpay.amazonaws.com"
KID = "agent-pay-key-1"

# A fixed buyer account id derived from the (loosely validated) SigV4 identity.
# Must be 12 digits to satisfy the SDK's PaymentDetail/PaymentSummary schemas.
BUYER_ACCOUNT_ID = "111122223333"

app = Flask(__name__)


def _b64url(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --- ES384 signing key (matches production Agent Pay) ------------------------
_private_key = generate_private_key(SECP384R1())
_numbers = _private_key.public_key().public_numbers()
PUBLIC_JWK: dict[str, Any] = {
    "kty": "EC",
    "crv": "P-384",
    "x": _b64url(_numbers.x.to_bytes(48, "big")),
    "y": _b64url(_numbers.y.to_bytes(48, "big")),
    "kid": KID,
    "use": "sig",
    "alg": "ES384",
}

# In-memory stores.
_payments: dict[str, dict[str, Any]] = {}
_client_tokens: dict[str, dict[str, Any]] = {}  # idempotency: clientToken -> record


def _require_sigv4() -> bool:
    """Loosely validate SigV4: accept any AWS4-HMAC-SHA256 Authorization header.

    The mock accepts unauthenticated requests too (for quick curl tests) but
    rejects a *wrong* auth scheme, matching the reference mock's behavior.
    """
    auth = request.headers.get("authorization", "")
    return not auth or "AWS4-HMAC-SHA256" in auth


@app.post("/CreateAgentPayment")
def create_agent_payment() -> Response:
    """Mint a payment token JWT that embeds the seller's quote token."""
    if not _require_sigv4():
        return _error(403, "SigV4 authentication required")

    body = request.get_json(silent=True) or {}
    quote_token = body.get("quoteToken")
    client_token = body.get("clientToken")

    if not isinstance(quote_token, str) or not quote_token:
        return _error(400, "quoteToken is required and must be a string")

    # Idempotency: same clientToken + same quoteToken returns the cached payment;
    # same clientToken + different quoteToken is a 409 conflict.
    if client_token and client_token in _client_tokens:
        existing = _client_tokens[client_token]
        if existing["quoteToken"] == quote_token:
            return _created(existing)
        return _error(
            409,
            "The same clientToken was used with different request parameters. "
            "Use a new clientToken for a different request.",
        )

    # Parse the quote (no signature check — the seller's facilitator verifies it).
    try:
        quote_claims = pyjwt.decode(quote_token, options={"verify_signature": False})
    except Exception:  # noqa: BLE001 - any decode failure is a bad quote
        return _error(400, "The quote token is not a valid JWT and cannot be parsed.")

    now = int(time.time())
    if quote_claims.get("exp") and quote_claims["exp"] < now:
        return _error(400, "The quote token exp claim is in the past.")

    price = quote_claims.get("price")
    if isinstance(price, list):
        price = price[0] if price else None
    if not isinstance(price, dict) or not price.get("currency"):
        return _error(400, "The quote token is missing price information.")
    if price["currency"] != "USD":
        return _error(400, "Only USD is supported.")

    payment_id = f"awsmp-{uuid.uuid4()}"

    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": BUYER_ACCOUNT_ID,
        "iat": now,
        "exp": now + 3600,
        "payment_id": payment_id,
        "quote_token": quote_token,
        "payment_context": {"transaction_id": payment_id, "quote_token": quote_token},
    }

    payment_token = pyjwt.encode(claims, _private_key, algorithm="ES384", headers={"kid": KID})
    created_at = _iso_utc(now)

    issuer = quote_claims.get("iss") or "unknown-seller"
    record = {
        "paymentId": payment_id,
        "buyerAccountId": BUYER_ACCOUNT_ID,
        "sellerInformation": {"sellerProfileId": issuer, "displayName": issuer},
        "productId": (quote_claims.get("settlement") or {}).get("product_id")
        or quote_claims.get("reference")
        or "lst-default",
        "quoteToken": quote_token,
        "paymentToken": payment_token,
        "createdAt": created_at,
        "amount": {"value": price["amount"], "currency": price["currency"]},
    }
    _payments[payment_id] = record
    if client_token:
        _client_tokens[client_token] = record

    print(f"  [agent-pay] created {payment_id}  ({price['amount']} {price['currency']})")
    return _created(record)


@app.get("/GetAgentPayment/<payment_id>")
def get_agent_payment(payment_id: str) -> Response:
    """Return a stored payment by id."""
    if not _require_sigv4():
        return _error(403, "SigV4 authentication required")

    record = _payments.get(payment_id)
    if record is None:
        return _error(404, f"Payment not found: {payment_id}")

    return jsonify(
        {
            "payment": {
                "paymentId": record["paymentId"],
                "buyerAccountId": record["buyerAccountId"],
                "sellerInformation": record["sellerInformation"],
                "productId": record["productId"],
                "quoteToken": record["quoteToken"],
                "paymentToken": record["paymentToken"],
                "createdAt": record["createdAt"],
                "amount": record["amount"],
            }
        }
    )


@app.post("/ListAgentPayments")
def list_agent_payments() -> Response:
    """List payments created by the (fixed) caller, newest first."""
    if not _require_sigv4():
        return _error(403, "SigV4 authentication required")

    mine = [p for p in _payments.values() if p["buyerAccountId"] == BUYER_ACCOUNT_ID]
    mine.sort(key=lambda p: p["createdAt"], reverse=True)
    return jsonify(
        {
            "payments": [
                {
                    "paymentId": p["paymentId"],
                    "buyerAccountId": p["buyerAccountId"],
                    "sellerInformation": p["sellerInformation"],
                    "productId": p["productId"],
                    "createdAt": p["createdAt"],
                }
                for p in mine
            ]
        }
    )


@app.get("/.well-known/jwks.json")
def jwks() -> Response:
    """Publish the payment-token signing public key."""
    return jsonify({"keys": [PUBLIC_JWK]})


@app.get("/health")
def health() -> Response:
    """Liveness probe."""
    return jsonify({"status": "healthy", "payments": len(_payments)})


def _created(record: dict[str, Any]) -> Response:
    resp = jsonify(
        {
            "paymentId": record["paymentId"],
            "paymentToken": record["paymentToken"],
            "createdAt": record["createdAt"],
        }
    )
    resp.status_code = 201
    return resp


def _error(status: int, message: str) -> Response:
    resp = jsonify({"message": message})
    resp.status_code = status
    return resp


def _iso_utc(epoch: int) -> str:
    """Format an epoch second as an ISO 8601 UTC timestamp (``...Z``)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


if __name__ == "__main__":
    print("")
    print("🏦  Mock AWS Marketplace Agent Pay Service")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"   Base URL: http://localhost:{PORT}")
    print(f"   Issuer:   {ISSUER}   Signing: ES384 (kid={KID})")
    print("   POST /CreateAgentPayment   GET /GetAgentPayment/<id>")
    print("   POST /ListAgentPayments    GET /.well-known/jwks.json")
    print("   Auth: SigV4 (accepts any AWS4-HMAC-SHA256 request)")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    app.run(port=PORT)
