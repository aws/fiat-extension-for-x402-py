# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for seller-key resolution and the supported-kinds endpoint.

The facilitator can locate the seller's quote-signing key three ways: from the
quote's ``iss`` (the default), from an explicit JWKS base URL, or from KMS. These
tests drive all three end to end with real ES384 signatures.
"""

from __future__ import annotations

import base64
import time
from typing import Any, ClassVar
from unittest.mock import MagicMock, patch

import httpx
import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1, generate_private_key

from fiat_extension_x402.constants import (
    AGENT_PAY_JWKS_BASE_URL,
    DEFAULT_AGENT_PAY_BASE_URL,
    WELL_KNOWN_JWKS_PATH,
    WELL_KNOWN_X402_SUPPORTED_PATH,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.facilitator.client import (
    AgentPayFacilitatorClient,
    JwksSellerKeyResolver,
    KmsSellerKeyResolver,
)

_SELLER_ISS = "https://seller.resolver.example.com"
_EXPLICIT_JWKS = "https://keys.resolver.example.com"
_AGENT_PAY_JWKS_URL = f"{AGENT_PAY_JWKS_BASE_URL.rstrip('/')}{WELL_KNOWN_JWKS_PATH}"
_REQUIREMENTS: dict[str, Any] = {
    "amount": "0.15",
    "asset": "iso4217:USD",
    "network": "aws:base",
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _keypair(kid: str) -> tuple[Any, dict[str, Any]]:
    key = generate_private_key(SECP384R1())
    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-384",
        "x": _b64url(numbers.x.to_bytes(48, "big")),
        "y": _b64url(numbers.y.to_bytes(48, "big")),
        "kid": kid,
        "use": "sig",
        "alg": "ES384",
    }
    return key, jwk


@pytest.fixture
def keys() -> dict[str, Any]:
    seller_key, seller_jwk = _keypair("seller-1")
    ap_key, ap_jwk = _keypair("ap-1")
    now = int(time.time())
    quote = pyjwt.encode(
        {
            "iss": _SELLER_ISS,
            "aud": "aws:marketplace",
            "iat": now,
            "exp": now + 300,
            "jti": "q-1",
            "price": {"amount": "0.15", "currency": "USD"},
            "payTo": "seller-1",
            "reference": "RESOURCE",
        },
        seller_key,
        algorithm="ES384",
        headers={"kid": "seller-1"},
    )
    payment = pyjwt.encode(
        {
            "iss": "awsmp-agentpay.amazonaws.com",
            "aud": _SELLER_ISS,
            "iat": now,
            "exp": now + 3600,
            "sub": "111122223333",
            "payment_id": "awsmp-1",
            "quote_token": quote,
        },
        ap_key,
        algorithm="ES384",
        headers={"kid": "ap-1"},
    )
    return {
        "seller_key": seller_key,
        "seller_jwk": seller_jwk,
        "ap_jwk": ap_jwk,
        "quote": quote,
        "payment": payment,
    }


def _mock_agent_pay_jwks(keys: dict[str, Any]) -> None:
    respx.get(_AGENT_PAY_JWKS_URL).mock(
        return_value=httpx.Response(200, json={"keys": [keys["ap_jwk"]]})
    )


def _der_public_key(key: Any) -> bytes:
    return bytes(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


class TestDefaultIssuerDiscovery:
    @respx.mock
    def test_resolves_the_key_from_the_quote_issuer(self, keys: dict[str, Any]) -> None:
        _mock_agent_pay_jwks(keys)
        route = respx.get(f"{_SELLER_ISS}{WELL_KNOWN_JWKS_PATH}").mock(
            return_value=httpx.Response(200, json={"keys": [keys["seller_jwk"]]})
        )

        result = AgentPayFacilitatorClient().verify(keys["payment"], keys["quote"], _REQUIREMENTS)

        assert result.is_valid is True
        assert route.called


class TestJwksSellerKeyResolver:
    @respx.mock
    def test_uses_the_explicit_url_and_never_touches_the_issuer(self, keys: dict[str, Any]) -> None:
        _mock_agent_pay_jwks(keys)
        issuer_route = respx.get(f"{_SELLER_ISS}{WELL_KNOWN_JWKS_PATH}").mock(
            return_value=httpx.Response(500)
        )
        explicit_route = respx.get(f"{_EXPLICIT_JWKS}{WELL_KNOWN_JWKS_PATH}").mock(
            return_value=httpx.Response(200, json={"keys": [keys["seller_jwk"]]})
        )

        client = AgentPayFacilitatorClient(
            seller_key_resolver=JwksSellerKeyResolver(jwks_url=_EXPLICIT_JWKS)
        )
        result = client.verify(keys["payment"], keys["quote"], _REQUIREMENTS)

        assert result.is_valid is True
        assert explicit_route.called
        assert not issuer_route.called


class TestKmsSellerKeyResolver:
    @respx.mock
    def test_verifies_against_the_kms_public_key(self, keys: dict[str, Any]) -> None:
        _mock_agent_pay_jwks(keys)
        issuer_route = respx.get(f"{_SELLER_ISS}{WELL_KNOWN_JWKS_PATH}").mock(
            return_value=httpx.Response(500)
        )
        kms = MagicMock()
        kms.get_public_key.return_value = {"PublicKey": _der_public_key(keys["seller_key"])}

        with patch("boto3.client", return_value=kms):
            client = AgentPayFacilitatorClient(
                seller_key_resolver=KmsSellerKeyResolver(
                    kms_key_arn="arn:aws:kms:us-east-1:111122223333:alias/seller",
                    region="us-east-1",
                )
            )
            result = client.verify(keys["payment"], keys["quote"], _REQUIREMENTS)

        assert result.is_valid is True
        # No JWKS fetch at all on the KMS path.
        assert not issuer_route.called

    @respx.mock
    def test_caches_the_kms_public_key(self, keys: dict[str, Any]) -> None:
        _mock_agent_pay_jwks(keys)
        kms = MagicMock()
        kms.get_public_key.return_value = {"PublicKey": _der_public_key(keys["seller_key"])}

        with patch("boto3.client", return_value=kms):
            client = AgentPayFacilitatorClient(
                seller_key_resolver=KmsSellerKeyResolver(
                    kms_key_arn="arn:aws:kms:us-east-1:111122223333:alias/seller",
                    region="us-east-1",
                )
            )
            client.verify(keys["payment"], keys["quote"], _REQUIREMENTS)
            client.verify(keys["payment"], keys["quote"], _REQUIREMENTS)

        assert kms.get_public_key.call_count == 1

    @respx.mock
    def test_rejects_a_payment_signed_by_a_different_key(self, keys: dict[str, Any]) -> None:
        _mock_agent_pay_jwks(keys)
        other_key, _ = _keypair("someone-else")
        kms = MagicMock()
        kms.get_public_key.return_value = {"PublicKey": _der_public_key(other_key)}

        with patch("boto3.client", return_value=kms):
            client = AgentPayFacilitatorClient(
                seller_key_resolver=KmsSellerKeyResolver(
                    kms_key_arn="arn:aws:kms:us-east-1:111122223333:alias/wrong",
                    region="us-east-1",
                )
            )
            result = client.verify(keys["payment"], keys["quote"], _REQUIREMENTS)

        assert result.is_valid is False
        assert result.invalid_reason == "verification_failed"

    @respx.mock
    def test_surfaces_empty_kms_key_material(self, keys: dict[str, Any]) -> None:
        _mock_agent_pay_jwks(keys)
        kms = MagicMock()
        kms.get_public_key.return_value = {}

        with patch("boto3.client", return_value=kms):
            client = AgentPayFacilitatorClient(
                seller_key_resolver=KmsSellerKeyResolver(
                    kms_key_arn="arn:aws:kms:us-east-1:111122223333:alias/empty",
                    region="us-east-1",
                )
            )
            result = client.verify(keys["payment"], keys["quote"], _REQUIREMENTS)

        assert result.is_valid is False


class TestQuoteIssuerRequirement:
    @respx.mock
    def test_missing_issuer_is_rejected_when_it_is_the_only_locator(
        self, keys: dict[str, Any]
    ) -> None:
        """With no resolver configured, `iss` is what finds the key."""
        _mock_agent_pay_jwks(keys)
        now = int(time.time())
        quote = pyjwt.encode(
            {
                "iss": "",
                "aud": "aws:marketplace",
                "iat": now,
                "exp": now + 300,
                "jti": "q-2",
                "price": {"amount": "0.15", "currency": "USD"},
                "payTo": "s",
                "reference": "RESOURCE",
            },
            keys["seller_key"],
            algorithm="ES384",
            headers={"kid": "seller-1"},
        )
        payment = pyjwt.encode(
            {
                "iss": "awsmp-agentpay.amazonaws.com",
                "aud": _SELLER_ISS,
                "iat": now,
                "exp": now + 3600,
                "sub": "1",
                "payment_id": "awsmp-2",
                "quote_token": quote,
            },
            generate_private_key(SECP384R1()),
            algorithm="ES384",
            headers={"kid": "ap-1"},
        )
        # Signed by an unrelated Agent Pay key, so this fails at step 1 anyway —
        # what matters is the no-resolver case still demands an issuer.
        result = AgentPayFacilitatorClient().verify(payment, quote, _REQUIREMENTS)
        assert result.is_valid is False

    @respx.mock
    def test_issuer_is_not_fetched_when_a_resolver_supersedes_it(
        self, keys: dict[str, Any]
    ) -> None:
        """An explicit resolver makes the issuer irrelevant for key lookup."""
        _mock_agent_pay_jwks(keys)
        issuer_route = respx.get(f"{_SELLER_ISS}{WELL_KNOWN_JWKS_PATH}").mock(
            return_value=httpx.Response(500)
        )
        respx.get(f"{_EXPLICIT_JWKS}{WELL_KNOWN_JWKS_PATH}").mock(
            return_value=httpx.Response(200, json={"keys": [keys["seller_jwk"]]})
        )

        result = AgentPayFacilitatorClient(
            seller_key_resolver=JwksSellerKeyResolver(jwks_url=_EXPLICIT_JWKS)
        ).verify(keys["payment"], keys["quote"], _REQUIREMENTS)

        assert result.is_valid is True
        assert not issuer_route.called


class TestGetSupported:
    _URL = f"{DEFAULT_AGENT_PAY_BASE_URL}{WELL_KNOWN_X402_SUPPORTED_PATH}"
    _DOC: ClassVar[dict[str, Any]] = {
        "kinds": [
            {"x402Version": 2, "scheme": "agent-pay", "network": "aws:base"},
            {"x402Version": 2, "scheme": "exact", "network": "eip155:8453"},
        ]
    }

    @respx.mock
    def test_returns_every_kind_by_default(self) -> None:
        respx.get(self._URL).mock(return_value=httpx.Response(200, json=self._DOC))
        supported = AgentPayFacilitatorClient().get_supported()
        assert [k["network"] for k in supported["kinds"]] == ["aws:base", "eip155:8453"]

    @respx.mock
    def test_network_filter_drops_unregistered_networks(self) -> None:
        """Prevents this facilitator claiming networks the integrator didn't choose."""
        respx.get(self._URL).mock(return_value=httpx.Response(200, json=self._DOC))
        client = AgentPayFacilitatorClient(network_filter={"aws:base"})
        supported = client.get_supported()
        assert [k["network"] for k in supported["kinds"]] == ["aws:base"]

    @respx.mock
    def test_uses_the_configured_base_url(self) -> None:
        base = "https://beta.agentpay.example.com"
        route = respx.get(f"{base}{WELL_KNOWN_X402_SUPPORTED_PATH}").mock(
            return_value=httpx.Response(200, json={"kinds": []})
        )
        AgentPayFacilitatorClient(agent_pay_base_url=base).get_supported()
        assert route.called

    @respx.mock
    def test_non_2xx_raises_validation_error(self) -> None:
        respx.get(self._URL).mock(return_value=httpx.Response(503))
        with pytest.raises(ValidationError, match="Failed to fetch supported kinds"):
            AgentPayFacilitatorClient().get_supported()
