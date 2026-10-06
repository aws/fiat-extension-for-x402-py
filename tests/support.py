# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test doubles: key pairs, a fake payment service, and DPoP proofs.

The payment service issues payment tokens in production; tests mint them with a
local key so the seller and facilitator code paths can be exercised offline.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from fiat_extension_x402.constants import PAYMENT_TOKEN_ISSUER
from fiat_extension_x402.dpop import compute_jwk_thumbprint
from fiat_extension_x402.signers import LocalQuoteSigner

SERVICE_JWKS_BASE_URL = "https://jwks.payments.test"
SELLER_URL = "https://seller.example.com"


def _b64(n: int, length: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


_P256 = ec.SECP256R1()


def ec_key(
    kid: str, curve: ec.EllipticCurve = _P256, alg: str = "ES256"
) -> tuple[ec.EllipticCurvePrivateKey, dict[str, str]]:
    """Return an EC private key and its public JWK."""
    private_key = ec.generate_private_key(curve)
    numbers = private_key.public_key().public_numbers()
    size = (curve.key_size + 7) // 8
    crv = {"secp256r1": "P-256", "secp384r1": "P-384"}[curve.name]
    jwk = {
        "kty": "EC",
        "crv": crv,
        "x": _b64(numbers.x, size),
        "y": _b64(numbers.y, size),
        "kid": kid,
        "alg": alg,
    }
    return private_key, jwk


def seller_signer(service_url: str = SELLER_URL) -> LocalQuoteSigner:
    """A local quote signer for the test seller."""
    private_key, jwk = ec_key("seller-key")
    return LocalQuoteSigner(private_key, jwk, service_url)


@dataclass
class FakePaymentService:
    """Issues payment tokens the way the payment service does."""

    private_key: ec.EllipticCurvePrivateKey = field(init=False)
    jwk: dict[str, str] = field(init=False)

    def __post_init__(self) -> None:
        self.private_key, self.jwk = ec_key("service-key", ec.SECP384R1(), "ES384")

    @property
    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.jwk]}

    def issue(
        self,
        quote_token: str,
        *,
        audience: str = SELLER_URL,
        buyer: str = "123456789012",
        dpop_jwk: dict[str, str] | None = None,
        issuer: str = PAYMENT_TOKEN_ISSUER,
        expires_in: int = 300,
    ) -> str:
        now = int(time.time())
        payment_id = f"awsmp-{uuid.uuid4()}"
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "sub": buyer,
            "payment_id": payment_id,
            "jti": payment_id,
            "quote_token": quote_token,
            "iat": now,
            "exp": now + expires_in,
        }
        if dpop_jwk is not None:
            claims["cnf"] = {"jkt": compute_jwk_thumbprint(dpop_jwk)}
        token: str = jwt.encode(
            claims, self.private_key, algorithm="ES384", headers={"kid": self.jwk["kid"]}
        )
        return token


def dpop_proof(
    private_key: ec.EllipticCurvePrivateKey,
    jwk: dict[str, str],
    *,
    htm: str,
    htu: str,
    access_token: str | None = None,
    iat: int | None = None,
) -> str:
    """Create a DPoP proof (RFC 9449) as a buyer would."""
    public_jwk = {k: jwk[k] for k in ("kty", "crv", "x", "y")}
    claims: dict[str, Any] = {
        "jti": str(uuid.uuid4()),
        "htm": htm,
        "htu": htu,
        "iat": iat if iat is not None else int(time.time()),
    }
    if access_token is not None:
        digest = hashlib.sha256(access_token.encode("ascii")).digest()
        claims["ath"] = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    token: str = jwt.encode(
        claims, private_key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": public_jwk}
    )
    return token


def encode_header(value: dict[str, Any]) -> str:
    """Base64-encode a JSON payment payload for the PAYMENT-SIGNATURE header."""
    return base64.b64encode(json.dumps(value).encode()).decode()


def decode_header(value: str) -> dict[str, Any]:
    """Decode a base64 JSON header (PAYMENT-REQUIRED, PAYMENT-RESPONSE)."""
    decoded: dict[str, Any] = json.loads(base64.b64decode(value))
    return decoded
