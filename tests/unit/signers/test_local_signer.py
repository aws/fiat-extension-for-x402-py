# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for local signers."""

from __future__ import annotations

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.signers.local import to_agent_pay_signer, to_service_agent_pay_signer


class TestLocalServiceSigner:
    @pytest.mark.asyncio
    async def test_sign_quote(self) -> None:
        key = generate_private_key(SECP256R1())
        public_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES256"}
        signer = to_service_agent_pay_signer(key, public_jwk, "https://seller.example.com")

        token = await signer.sign_quote(
            {"iss": "test", "price": [{"amount": "1.00", "currency": "USD"}]}
        )
        assert isinstance(token, str)
        claims = pyjwt.decode(token, options={"verify_signature": False})
        assert claims["iss"] == "test"

    def test_get_public_key(self) -> None:
        key = generate_private_key(SECP256R1())
        public_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES256"}
        signer = to_service_agent_pay_signer(key, public_jwk, "https://seller.example.com")
        assert signer.get_public_key() == public_jwk

    def test_get_service_url(self) -> None:
        key = generate_private_key(SECP256R1())
        public_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES256"}
        signer = to_service_agent_pay_signer(key, public_jwk, "https://seller.example.com")
        assert signer.get_service_url() == "https://seller.example.com"

    def test_empty_service_url_raises_validation_error(self) -> None:
        key = generate_private_key(SECP256R1())
        public_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES256"}
        with pytest.raises(ValidationError, match="service_url is required"):
            to_service_agent_pay_signer(key, public_jwk, "")

    def test_whitespace_service_url_raises_validation_error(self) -> None:
        key = generate_private_key(SECP256R1())
        public_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES256"}
        with pytest.raises(ValidationError, match="service_url is required"):
            to_service_agent_pay_signer(key, public_jwk, "   ")


class TestLocalAgentPaySigner:
    @pytest.mark.asyncio
    async def test_sign(self) -> None:
        key = generate_private_key(SECP256R1())
        public_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES256"}
        signer = to_agent_pay_signer(key, public_jwk, "agent-id")

        token = await signer.sign({"sub": "buyer"})
        assert isinstance(token, str)

    def test_get_agent_pay_id(self) -> None:
        key = generate_private_key(SECP256R1())
        public_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES256"}
        signer = to_agent_pay_signer(key, public_jwk, "agent-id-123")
        assert signer.get_agent_pay_id() == "agent-id-123"


class TestLocalAgentPaySignerSign:
    """Cover the sign method of _LocalAgentPaySigner (line 76)."""

    @pytest.mark.asyncio
    async def test_sign_returns_jwt(self) -> None:
        key = generate_private_key(SECP256R1())
        public_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES256"}
        signer = to_agent_pay_signer(key, public_jwk, "ap-id")
        token = await signer.sign({"iss": "agentpay", "payment_id": "p1"})
        claims = pyjwt.decode(token, options={"verify_signature": False})
        assert claims["iss"] == "agentpay"
        assert claims["payment_id"] == "p1"

    def test_get_public_key(self) -> None:
        key = generate_private_key(SECP256R1())
        public_jwk = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES256"}
        signer = to_agent_pay_signer(key, public_jwk, "ap-id")
        assert signer.get_public_key() == public_jwk
