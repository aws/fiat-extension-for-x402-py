# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Harness for in-process Agent Pay integration tests.

Wires the SDK's real components — server scheme, local signers, and the
facilitator client — into the full buyer -> Agent Pay -> seller flow, with all
HTTP (the seller and Agent Pay JWKS endpoints) served from in-memory ``respx``
mocks. No network, no credentials, no environment gating: these run as part of
the default unit suite.

This is the in-process analog of the reference SDK's ``test/integrations`` suite
(the framework-driven client/server/facilitator round-trips). The Python SDK has
a flatter shape, so the harness composes the equivalent behavior directly:
``enhance_payment_requirements`` (seller) -> a mock Agent Pay issuing a payment
token -> ``AgentPayFacilitatorClient.verify`` / ``settle`` (seller).
"""

from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP384R1,
    EllipticCurvePrivateKey,
    generate_private_key,
)

from fiat_extension_x402.constants import AGENT_PAY_JWKS_BASE_URL, WELL_KNOWN_JWKS_PATH

_AGENT_PAY_JWKS_URL = f"{AGENT_PAY_JWKS_BASE_URL.rstrip('/')}{WELL_KNOWN_JWKS_PATH}"
_SERVICE_URL = "https://seller.integration.example.com"
_SELLER_JWKS_URL = f"{_SERVICE_URL}{WELL_KNOWN_JWKS_PATH}"
_AGENT_PAY_ISS = "awsmp-agentpay.amazonaws.com"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _ec384_keypair(kid: str) -> tuple[EllipticCurvePrivateKey, dict[str, Any]]:
    """Generate an ES384 key pair and its public JWK with the given kid."""
    private_key = generate_private_key(SECP384R1())
    numbers = private_key.public_key().public_numbers()
    jwk: dict[str, Any] = {
        "kty": "EC",
        "crv": "P-384",
        "x": _b64url(numbers.x.to_bytes(48, "big")),
        "y": _b64url(numbers.y.to_bytes(48, "big")),
        "kid": kid,
        "use": "sig",
        "alg": "ES384",
    }
    return private_key, jwk


@dataclass
class IntegrationHarness:
    """Real SDK components wired for the in-process payment flow."""

    seller_signer: Any
    agent_pay_id: str
    _agent_pay_key: EllipticCurvePrivateKey
    _agent_pay_jwk: dict[str, Any]
    _seller_jwk: dict[str, Any]

    async def build_quote(
        self,
        *,
        network: str = "aws:base",
        amount: str = "0.15",
        currency: str = "USD",
        pay_to: str = "service-pay",
    ) -> tuple[dict[str, Any], str]:
        """Seller leg: enhance requirements via the SDK server scheme.

        Returns ``(requirements, quote_token)``.
        """
        from fiat_extension_x402 import enhance_payment_requirements

        base: dict[str, Any] = {
            "scheme": "agent-pay",
            "network": network,
            "amount": amount,
            "asset": f"iso4217:{currency}",
            "payTo": pay_to,
            "maxTimeoutSeconds": 300,
            "extra": {},
        }
        requirements = await enhance_payment_requirements(base, self.seller_signer)
        return requirements, requirements["extra"]["quoteToken"]

    def issue_payment_token(
        self,
        quote_token: str,
        *,
        sub: str | None = None,
        cnf_jkt: str | None = None,
        exp_offset: int = 3600,
    ) -> str:
        """Mock Agent Pay: issue a payment token JWT embedding the quote."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": _AGENT_PAY_ISS,
            "aud": _SERVICE_URL,
            "iat": now,
            "exp": now + exp_offset,
            "payment_id": f"awsmp-{uuid.uuid4()}",
            "quote_token": quote_token,
        }
        if sub is not None:
            claims["sub"] = sub
        if cnf_jkt is not None:
            claims["cnf"] = {"jkt": cnf_jkt}
        token: str = pyjwt.encode(
            claims,
            self._agent_pay_key,
            algorithm="ES384",
            headers={"kid": self._agent_pay_jwk["kid"]},
        )
        return token

    def mock_jwks(self, respx_mock: Any) -> None:
        """Register the seller + Agent Pay JWKS endpoints on a respx router."""
        import httpx

        respx_mock.get(_AGENT_PAY_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [self._agent_pay_jwk]})
        )
        respx_mock.get(_SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [self._seller_jwk]})
        )


@pytest.fixture
def harness() -> IntegrationHarness:
    """Build a fresh integration harness with real seller + Agent Pay signers."""
    from fiat_extension_x402 import to_service_agent_pay_signer

    seller_key, seller_jwk = _ec384_keypair("seller-int-key")
    agent_pay_key, agent_pay_jwk = _ec384_keypair("agentpay-int-key")

    seller_signer = to_service_agent_pay_signer(seller_key, seller_jwk, _SERVICE_URL)

    return IntegrationHarness(
        seller_signer=seller_signer,
        agent_pay_id="agent-pay-integration-123",
        _agent_pay_key=agent_pay_key,
        _agent_pay_jwk=agent_pay_jwk,
        _seller_jwk=seller_jwk,
    )
