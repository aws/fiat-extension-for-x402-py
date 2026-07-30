# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for AgentPayFacilitatorClient.

Covers:
- Valid payment token verification with real ES384 signature
- Signature mismatch (wrong key / tampered token)
- Expired payment token
- Missing quote_token in claims
- Mismatched embedded quote_token
- Amount/currency mismatch
- Seller JWKS caching
- Settle no-op returns success
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP384R1,
    EllipticCurvePrivateKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as generate_rsa_key

from fiat_extension_x402.facilitator import (
    AgentPayFacilitatorClient,
    SettleResponse,
)

# ============================================================================
# Test Fixtures — real ES384 key pairs
# ============================================================================

_AGENT_PAY_JWKS_URL = "https://d3aeb2cjjowogc.cloudfront.net/.well-known/jwks.json"
_SELLER_BASE_URL = "https://api.seller.example.com"
_SELLER_JWKS_URL = f"{_SELLER_BASE_URL}/.well-known/jwks.json"

# Requirements matching the default quote token (0.10 USD).
_DEFAULT_REQUIREMENTS: dict[str, Any] = {
    "amount": "0.10",
    "asset": "iso4217:USD",
    "network": "aws:base",
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _generate_ec384_key_pair() -> tuple[EllipticCurvePrivateKey, dict[str, object]]:
    """Generate an ES384 key pair and return (private_key, jwk_dict)."""
    private_key = generate_private_key(SECP384R1())
    public_key = private_key.public_key()

    numbers = public_key.public_numbers()
    x_bytes = numbers.x.to_bytes(48, byteorder="big")
    y_bytes = numbers.y.to_bytes(48, byteorder="big")

    jwk: dict[str, object] = {
        "kty": "EC",
        "crv": "P-384",
        "x": _b64url(x_bytes),
        "y": _b64url(y_bytes),
        "kid": "test-key-1",
        "use": "sig",
        "alg": "ES384",
    }
    return private_key, jwk


def _sign_jwt(
    claims: dict[str, Any],
    private_key: Any,
    kid: str = "test-key-1",
    algorithm: str = "ES384",
) -> str:
    """Sign a JWT with the given private key."""
    return pyjwt.encode(claims, private_key, algorithm=algorithm, headers={"kid": kid})


def _make_jwks(jwk: dict[str, object]) -> dict[str, list[dict[str, object]]]:
    """Wrap a JWK in a JWKS document."""
    return {"keys": [jwk]}


# Pre-generate key pairs for Agent Pay and the seller.
_AP_PRIVATE_KEY, _AP_JWK = _generate_ec384_key_pair()
_SELLER_PRIVATE_KEY, _SELLER_JWK = _generate_ec384_key_pair()


def _make_quote_token(
    *,
    iss: str = _SELLER_BASE_URL,
    exp: int | None = None,
    amount: str = "0.10",
    currency: str = "USD",
) -> str:
    """Create a real seller-signed quote token JWT."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": iss,
        "aud": "aws:marketplace",
        "iat": now,
        "exp": exp if exp is not None else now + 300,
        "jti": "quote-id-001",
        "price": {"amount": amount, "currency": currency},
        "payTo": "seller-profile-123",
        "reference": "RESOURCE",
    }
    return _sign_jwt(claims, _SELLER_PRIVATE_KEY)


def _make_payment_token(
    *,
    quote_token: str,
    exp: int | None = None,
    sub: str = "buyer-account-123",
    payment_id: str = "awsmp-01970f3e-4b2a-7dc0-8e1f-6a3b9c5d7e2f",
    include_quote: bool = True,
    cnf_jkt: str | None = None,
) -> str:
    """Create a real Agent Pay-signed payment token JWT."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "awsmp-agentpay.amazonaws.com",
        "sub": sub,
        "aud": _SELLER_BASE_URL,
        "iat": now,
        "exp": exp if exp is not None else now + 3600,
        "payment_id": payment_id,
    }
    if include_quote:
        claims["quote_token"] = quote_token
    if cnf_jkt is not None:
        claims["cnf"] = {"jkt": cnf_jkt}
    return _sign_jwt(claims, _AP_PRIVATE_KEY)


# ============================================================================
# Tests — verify()
# ============================================================================


@respx.mock
def test_verify_valid_token() -> None:
    """Valid payment token with correct signature passes verification."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))
    respx.get(_SELLER_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK)))

    quote_token = _make_quote_token()
    payment_token = _make_payment_token(quote_token=quote_token)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is True
    assert result.payer == "buyer-account-123"
    assert result.invalid_reason is None


@respx.mock
def test_verify_signature_mismatch_wrong_key() -> None:
    """Payment token signed with a different key fails verification."""
    _, wrong_jwk = _generate_ec384_key_pair()
    respx.get(_AGENT_PAY_JWKS_URL).mock(
        return_value=httpx.Response(200, json=_make_jwks(wrong_jwk))
    )

    quote_token = _make_quote_token()
    payment_token = _make_payment_token(quote_token=quote_token)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "verification_failed"


@respx.mock
def test_verify_tampered_token() -> None:
    """Tampered payment token (altered payload) fails signature verification."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))

    quote_token = _make_quote_token()
    payment_token = _make_payment_token(quote_token=quote_token)

    parts = payment_token.split(".")
    parts[1] = parts[1][:-4] + "XXXX"
    tampered_token = ".".join(parts)

    client = AgentPayFacilitatorClient()
    result = client.verify(tampered_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "verification_failed"


@respx.mock
def test_verify_expired_payment_token() -> None:
    """Expired payment token is rejected."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))

    quote_token = _make_quote_token()
    payment_token = _make_payment_token(quote_token=quote_token, exp=int(time.time()) - 10)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "payment_expired"
    assert result.invalid_message == "Payment token expired"


@respx.mock
def test_verify_missing_quote_token_in_claims() -> None:
    """Payment token without quote_token claim is rejected."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))

    quote_token = _make_quote_token()
    payment_token = _make_payment_token(quote_token=quote_token, include_quote=False)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "invalid_quote"
    assert "Missing quote token" in (result.invalid_message or "")


@respx.mock
def test_verify_quote_token_mismatch() -> None:
    """Mismatched embedded quote_token is rejected."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))

    quote_token = _make_quote_token()
    different_quote_token = _make_quote_token(amount="99.99")
    payment_token = _make_payment_token(quote_token=quote_token)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, different_quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "invalid_quote"
    assert "mismatch" in (result.invalid_message or "").lower()


@respx.mock
def test_verify_expired_quote_token() -> None:
    """An expired quote token is rejected even when the payment token is valid.

    The signature check runs with pyjwt's exp validation disabled, so the quote's
    own validity window has to be enforced explicitly.
    """
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))
    respx.get(_SELLER_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK)))

    quote_token = _make_quote_token(exp=int(time.time()) - 10)
    payment_token = _make_payment_token(quote_token=quote_token)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "quote_expired"
    assert "expired" in (result.invalid_message or "").lower()


@respx.mock
def test_verify_quote_token_without_issuer() -> None:
    """A quote token carrying no `iss` is rejected before any JWKS fetch."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))

    quote_token = _make_quote_token(iss="")
    payment_token = _make_payment_token(quote_token=quote_token)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "invalid_quote"
    assert "issuer" in (result.invalid_message or "").lower()


@respx.mock
def test_verify_amount_mismatch() -> None:
    """Amount mismatch between quote token and requirements is rejected."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))
    respx.get(_SELLER_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK)))

    quote_token = _make_quote_token(amount="0.10", currency="USD")
    payment_token = _make_payment_token(quote_token=quote_token)

    requirements: dict[str, Any] = {
        "amount": "5.00",
        "asset": "iso4217:USD",
        "network": "aws:base",
    }

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, requirements)

    assert result.is_valid is False
    assert result.invalid_reason == "invalid_payment"
    assert "mismatch" in (result.invalid_message or "").lower()


@respx.mock
def test_verify_jwks_fetch_failure() -> None:
    """JWKS fetch failure results in verification_error."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )

    quote_token = _make_quote_token()
    payment_token = _make_payment_token(quote_token=quote_token)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "verification_failed"


# ============================================================================
# Tests — settle()
# ============================================================================


def test_settle_returns_success() -> None:
    """Settle returns success immediately (auto-capture)."""
    client = AgentPayFacilitatorClient()
    result = client.settle(
        payment_id="awsmp-01970f3e-4b2a-7dc0-8e1f-6a3b9c5d7e2f",
        network="aws:base",
    )

    assert result == SettleResponse(
        success=True,
        transaction="awsmp-01970f3e-4b2a-7dc0-8e1f-6a3b9c5d7e2f",
        network="aws:base",
    )


def test_settle_different_network() -> None:
    """Settle preserves the provided network."""
    client = AgentPayFacilitatorClient()
    result = client.settle(payment_id="awsmp-abc123", network="aws:other")

    assert result.success is True
    assert result.transaction == "awsmp-abc123"
    assert result.network == "aws:other"


# ============================================================================
# Tests — verify with amount check passing
# ============================================================================


@respx.mock
def test_verify_with_matching_requirements() -> None:
    """Verification passes when requirements amounts match."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))
    respx.get(_SELLER_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK)))

    quote_token = _make_quote_token(amount="1.50", currency="EUR")
    payment_token = _make_payment_token(quote_token=quote_token)

    requirements: dict[str, Any] = {
        "amount": "1.50",
        "asset": "iso4217:EUR",
        "network": "aws:base",
    }

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, requirements)

    assert result.is_valid is True
    assert result.payer == "buyer-account-123"


# ============================================================================
# Tests — coverage for remaining branches
# ============================================================================


@respx.mock
def test_verify_legacy_payment_context_path() -> None:
    """Payment token with legacy payment_context.quote_token is supported."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))
    respx.get(_SELLER_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK)))

    quote_token = _make_quote_token()

    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "awsmp-agentpay.amazonaws.com",
        "sub": "buyer-legacy",
        "aud": _SELLER_BASE_URL,
        "iat": now,
        "exp": now + 3600,
        "payment_id": "awsmp-legacy-id",
        "payment_context": {
            "transaction_id": "aws:base:legacy-tx",
            "quote_token": quote_token,
        },
    }
    payment_token = _sign_jwt(claims, _AP_PRIVATE_KEY)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is True
    assert result.payer == "buyer-legacy"


@respx.mock
def test_verify_price_as_list() -> None:
    """Quote token with price as a list is handled correctly."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))
    respx.get(_SELLER_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK)))

    now = int(time.time())
    quote_claims: dict[str, Any] = {
        "iss": _SELLER_BASE_URL,
        "aud": "aws:marketplace",
        "iat": now,
        "exp": now + 300,
        "jti": "quote-list-price",
        "price": [
            {"amount": "2.00", "currency": "USD"},
            {"amount": "1.80", "currency": "EUR"},
        ],
        "payTo": "seller-123",
        "reference": "RESOURCE",
    }
    quote_token = _sign_jwt(quote_claims, _SELLER_PRIVATE_KEY)
    payment_token = _make_payment_token(quote_token=quote_token)

    requirements: dict[str, Any] = {
        "amount": "2.00",
        "asset": "iso4217:USD",
        "network": "aws:base",
    }

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, requirements)

    assert result.is_valid is True


@respx.mock
def test_verify_disallowed_algorithm() -> None:
    """Token signed with a disallowed algorithm is rejected."""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_data = _b64url(json.dumps({"iss": "test", "exp": int(time.time()) + 3600}).encode())
    sig = _b64url(b"x" * 32)
    fake_token = f"{header}.{payload_data}.{sig}"

    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))

    quote_token = _make_quote_token()
    client = AgentPayFacilitatorClient()
    result = client.verify(fake_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "verification_failed"
    assert "not allowed" in (result.invalid_message or "").lower()


@respx.mock
def test_verify_kid_mismatch_no_matching_key() -> None:
    """Token with kid that doesn't match any JWKS key is rejected."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))

    quote_token = _make_quote_token()
    payment_token = _sign_jwt(
        {
            "iss": "awsmp-agentpay.amazonaws.com",
            "sub": "buyer",
            "aud": _SELLER_BASE_URL,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "payment_id": "awsmp-123",
            "quote_token": quote_token,
        },
        _AP_PRIVATE_KEY,
        kid="nonexistent-kid",
    )

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "verification_failed"
    assert "no matching key" in (result.invalid_message or "").lower()


@respx.mock
def test_verify_malformed_jwk_raises_pyjwt_error() -> None:
    """Malformed JWK data that raises a JWT error is handled."""
    bad_jwk: dict[str, object] = {
        "kty": "EC",
        "crv": "P-384",
        "x": "AAAA",  # Too short / invalid
        "y": "BBBB",  # Too short / invalid
        "kid": "test-key-1",
        "use": "sig",
        "alg": "ES384",
    }
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json={"keys": [bad_jwk]}))

    quote_token = _make_quote_token()
    payment_token = _make_payment_token(quote_token=quote_token)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "verification_failed"


@respx.mock
def test_verify_unexpected_exception_in_token_verify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected non-PyJWT exception during verification is caught."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))

    quote_token = _make_quote_token()
    payment_token = _make_payment_token(quote_token=quote_token)

    # Force PyJWK key resolution to raise an unexpected error.
    monkeypatch.setattr(
        pyjwt.PyJWK,
        "from_dict",
        staticmethod(lambda _: (_ for _ in ()).throw(RuntimeError("unexpected"))),
    )

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "verification_failed"


@respx.mock
def test_verify_payer_none_when_sub_missing() -> None:
    """When sub is missing, payer is None (matches reference's sub-only behavior)."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))
    respx.get(_SELLER_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK)))

    quote_token = _make_quote_token()

    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "awsmp-agentpay.amazonaws.com",
        "aud": _SELLER_BASE_URL,
        "iat": now,
        "exp": now + 3600,
        "payment_id": "awsmp-no-sub",
        "quote_token": quote_token,
    }
    payment_token = _sign_jwt(claims, _AP_PRIVATE_KEY)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is True
    assert result.payer is None


@respx.mock
def test_verify_supports_rsa_key() -> None:
    """An RS256-signed token verifies against an RSA JWKS (allowlist includes RS256)."""
    rsa_private = generate_rsa_key(public_exponent=65537, key_size=2048)
    rsa_public_numbers = rsa_private.public_key().public_numbers()
    n_bytes = rsa_public_numbers.n.to_bytes((rsa_public_numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = rsa_public_numbers.e.to_bytes((rsa_public_numbers.e.bit_length() + 7) // 8, "big")
    rsa_jwk: dict[str, object] = {
        "kty": "RSA",
        "n": _b64url(n_bytes),
        "e": _b64url(e_bytes),
        "kid": "rsa-key-1",
        "use": "sig",
        "alg": "RS256",
    }

    # Agent Pay serves the RSA key; seller still uses EC.
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(rsa_jwk)))
    respx.get(_SELLER_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK)))

    quote_token = _make_quote_token()
    now = int(time.time())
    payment_token = _sign_jwt(
        {
            "iss": "awsmp-agentpay.amazonaws.com",
            "sub": "buyer-rsa",
            "aud": _SELLER_BASE_URL,
            "iat": now,
            "exp": now + 3600,
            "payment_id": "awsmp-rsa",
            "quote_token": quote_token,
        },
        rsa_private,
        kid="rsa-key-1",
        algorithm="RS256",
    )

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is True
    assert result.payer == "buyer-rsa"


@respx.mock
def test_verify_quote_signature_mismatch() -> None:
    """A quote token signed by a non-seller key fails the seller signature chain."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))
    # Seller JWKS serves a different key than the one that signed the quote.
    _wrong_seller_key, wrong_seller_jwk = _generate_ec384_key_pair()
    respx.get(_SELLER_JWKS_URL).mock(
        return_value=httpx.Response(200, json=_make_jwks(wrong_seller_jwk))
    )

    quote_token = _make_quote_token()
    payment_token = _make_payment_token(quote_token=quote_token)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "verification_failed"


@respx.mock
def test_verify_seller_jwks_non_200() -> None:
    """A non-200 from the seller JWKS endpoint fails verification."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))
    respx.get(_SELLER_JWKS_URL).mock(return_value=httpx.Response(503, text="Service Unavailable"))

    quote_token = _make_quote_token()
    payment_token = _make_payment_token(quote_token=quote_token)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is False
    assert result.invalid_reason == "verification_failed"


@respx.mock
def test_verify_quote_future_exp_passes() -> None:
    """A quote token whose exp is comfortably in the future verifies."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))
    respx.get(_SELLER_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK)))

    quote_token = _make_quote_token(exp=int(time.time()) + 600)
    payment_token = _make_payment_token(quote_token=quote_token)

    client = AgentPayFacilitatorClient()
    result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    assert result.is_valid is True


@respx.mock
def test_seller_jwks_is_cached() -> None:
    """The seller JWKS is fetched once and cached for subsequent verifications."""
    respx.get(_AGENT_PAY_JWKS_URL).mock(return_value=httpx.Response(200, json=_make_jwks(_AP_JWK)))
    seller_route = respx.get(_SELLER_JWKS_URL).mock(
        return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK))
    )

    quote_token = _make_quote_token()
    payment_token = _make_payment_token(quote_token=quote_token)

    client = AgentPayFacilitatorClient()
    client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)
    client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)

    # Seller JWKS fetched only once across two verifications.
    assert seller_route.call_count == 1


class TestDpopAwareVerification:
    """Verify that verify_options with DPoP proof is checked when cnf.jkt is present."""

    def test_no_verify_options_skips_dpop(self) -> None:
        """Without verify_options, DPoP is not checked (backward compat)."""
        from fiat_extension_x402.facilitator.client import AgentPayFacilitatorClient

        # This test verifies the method signature accepts None for verify_options
        client = AgentPayFacilitatorClient()
        # Will fail on JWKS fetch but that's fine — we just confirm the signature works
        result = client.verify("invalid-token", "qt", {})
        assert result.is_valid is False

    @respx.mock
    def test_dpop_thumbprint_mismatch_fails(self) -> None:
        """When cnf.jkt is present and DPoP proof thumbprint doesn't match, fail."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1 as _SECP256R1
        from cryptography.hazmat.primitives.asymmetric.ec import (
            generate_private_key as _generate_private_key,
        )

        from fiat_extension_x402.dpop import create_dpop_proof, generate_dpop_keypair
        from fiat_extension_x402.dpop.key_generation import _base64url_encode
        from fiat_extension_x402.facilitator.client import AgentPayFacilitatorClient

        # Create a signing key and build a valid payment token with cnf.jkt
        key = _generate_private_key(_SECP256R1())
        # Create the quote token (signed by seller)
        seller_key = _generate_private_key(_SECP256R1())
        quote_payload = {
            "iss": "https://seller.example.com",
            "aud": "aws:marketplace",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "jti": "q1",
            "price": [{"amount": "1.00", "currency": "USD"}],
            "payTo": "seller-1",
            "reference": "ref",
        }
        quote_token = pyjwt.encode(
            quote_payload, seller_key, algorithm="ES256", headers={"kid": "sk1"}
        )

        # Create payment token with cnf.jkt pointing to a DIFFERENT key
        payment_payload = {
            "iss": "awsmp-agentpay.amazonaws.com",
            "aud": "https://seller.example.com",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "sub": "buyer",
            "quote_token": quote_token,
            "cnf": {"jkt": "wrong-thumbprint-value"},
        }
        payment_token = pyjwt.encode(
            payment_payload, key, algorithm="ES256", headers={"kid": "pk1"}
        )

        # Mock JWKS endpoints
        pub_numbers = key.public_key().public_numbers()

        agent_pay_jwks: dict[str, Any] = {
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": _base64url_encode(pub_numbers.x.to_bytes(32, byteorder="big")),
                    "y": _base64url_encode(pub_numbers.y.to_bytes(32, byteorder="big")),
                    "kid": "pk1",
                    "alg": "ES256",
                }
            ]
        }
        seller_pub_numbers = seller_key.public_key().public_numbers()
        seller_jwks: dict[str, Any] = {
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": _base64url_encode(seller_pub_numbers.x.to_bytes(32, byteorder="big")),
                    "y": _base64url_encode(seller_pub_numbers.y.to_bytes(32, byteorder="big")),
                    "kid": "sk1",
                    "alg": "ES256",
                }
            ]
        }

        respx.get("https://d3aeb2cjjowogc.cloudfront.net/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=agent_pay_jwks)
        )
        respx.get("https://seller.example.com/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=seller_jwks)
        )

        # Create a DPoP proof from a DIFFERENT key pair (thumbprint won't match cnf.jkt)
        dpop_keypair = generate_dpop_keypair("ES256")
        dpop_proof = create_dpop_proof(
            dpop_keypair, {"htm": "POST", "htu": "https://seller.example.com/api"}
        )

        client = AgentPayFacilitatorClient()
        result = client.verify(
            payment_token,
            quote_token,
            {"amount": "1.00", "asset": "iso4217:USD"},
            verify_options={
                "dpop_proof": dpop_proof,
                "method": "POST",
                "url": "https://seller.example.com/api",
            },
        )
        assert result.is_valid is False
        assert result.invalid_reason == "dpop_invalid"

    @respx.mock
    def test_dpop_bound_without_proof_is_rejected(self) -> None:
        """A DPoP-bound token (cnf.jkt present) with no proof at all is rejected."""
        from fiat_extension_x402.dpop import generate_dpop_keypair
        from fiat_extension_x402.dpop.proof_verification import extract_dpop_thumbprint
        from fiat_extension_x402.dpop.proof_creation import create_dpop_proof

        dpop_keypair = generate_dpop_keypair("ES256")
        # Bind the payment token to the real DPoP key's thumbprint.
        bound_proof = create_dpop_proof(dpop_keypair, {"htm": "POST", "htu": "https://x/api"})
        jkt = extract_dpop_thumbprint(bound_proof)

        quote_token = _make_quote_token()
        now = int(time.time())
        payment_token = _sign_jwt(
            {
                "iss": "awsmp-agentpay.amazonaws.com",
                "sub": "buyer-dpop",
                "aud": _SELLER_BASE_URL,
                "iat": now,
                "exp": now + 3600,
                "payment_id": "awsmp-dpop",
                "quote_token": quote_token,
                "cnf": {"jkt": jkt},
            },
            _AP_PRIVATE_KEY,
        )

        respx.get(_AGENT_PAY_JWKS_URL).mock(
            return_value=httpx.Response(200, json=_make_jwks(_AP_JWK))
        )
        respx.get(_SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK))
        )

        client = AgentPayFacilitatorClient()
        # No verify_options provided at all — a bound token must still be rejected.
        result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)
        assert result.is_valid is False
        assert result.invalid_reason == "dpop_required"

    @respx.mock
    def test_dpop_matching_proof_passes(self) -> None:
        """A DPoP-bound token with a matching proof verifies successfully."""
        from fiat_extension_x402.dpop import generate_dpop_keypair
        from fiat_extension_x402.dpop.proof_verification import extract_dpop_thumbprint
        from fiat_extension_x402.dpop.proof_creation import create_dpop_proof

        dpop_keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(
            dpop_keypair, {"htm": "GET", "htu": "https://api.seller.com/data"}
        )
        jkt = extract_dpop_thumbprint(proof)

        quote_token = _make_quote_token()
        now = int(time.time())
        payment_token = _sign_jwt(
            {
                "iss": "awsmp-agentpay.amazonaws.com",
                "sub": "buyer-dpop-ok",
                "aud": _SELLER_BASE_URL,
                "iat": now,
                "exp": now + 3600,
                "payment_id": "awsmp-dpop-ok",
                "quote_token": quote_token,
                "cnf": {"jkt": jkt},
            },
            _AP_PRIVATE_KEY,
        )

        respx.get(_AGENT_PAY_JWKS_URL).mock(
            return_value=httpx.Response(200, json=_make_jwks(_AP_JWK))
        )
        respx.get(_SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK))
        )

        client = AgentPayFacilitatorClient()
        result = client.verify(
            payment_token,
            quote_token,
            _DEFAULT_REQUIREMENTS,
            verify_options={
                "dpop_proof": proof,
                "method": "GET",
                "url": "https://api.seller.com/data",
            },
        )
        assert result.is_valid is True
        assert result.payer == "buyer-dpop-ok"

    @respx.mock
    def test_no_cnf_passes_without_dpop(self) -> None:
        """A payment token without cnf is not DPoP-bound and passes with no proof."""
        respx.get(_AGENT_PAY_JWKS_URL).mock(
            return_value=httpx.Response(200, json=_make_jwks(_AP_JWK))
        )
        respx.get(_SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK))
        )

        quote_token = _make_quote_token()
        payment_token = _make_payment_token(quote_token=quote_token)

        client = AgentPayFacilitatorClient()
        result = client.verify(payment_token, quote_token, _DEFAULT_REQUIREMENTS)
        assert result.is_valid is True


class TestDpopRequestBinding:
    """A DPoP proof is only meaningful with the request it was bound to.

    Verifying signature and thumbprint but skipping htm/htu would prove key
    possession while silently dropping the request binding, letting a captured
    proof be replayed against a different method or endpoint.
    """

    @respx.mock
    def test_proof_without_method_and_url_is_rejected(self) -> None:
        from fiat_extension_x402.dpop import create_dpop_proof, generate_dpop_keypair
        from fiat_extension_x402.dpop.proof_verification import extract_dpop_thumbprint

        respx.get(_AGENT_PAY_JWKS_URL).mock(
            return_value=httpx.Response(200, json=_make_jwks(_AP_JWK))
        )
        respx.get(_SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK))
        )
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(keypair, {"htm": "GET", "htu": "https://api.example.com/r"})
        quote_token = _make_quote_token()
        payment_token = _make_payment_token(
            quote_token=quote_token, cnf_jkt=extract_dpop_thumbprint(proof)
        )

        result = AgentPayFacilitatorClient().verify(
            payment_token,
            quote_token,
            _DEFAULT_REQUIREMENTS,
            verify_options={"dpop_proof": proof},
        )

        assert result.is_valid is False
        assert result.invalid_reason == "dpop_invalid"
        assert "htm/htu" in (result.invalid_message or "")

    @respx.mock
    def test_method_comparison_is_case_insensitive(self) -> None:
        """A framework reporting a lowercase method must still verify."""
        from fiat_extension_x402.dpop import create_dpop_proof, generate_dpop_keypair
        from fiat_extension_x402.dpop.proof_verification import extract_dpop_thumbprint

        respx.get(_AGENT_PAY_JWKS_URL).mock(
            return_value=httpx.Response(200, json=_make_jwks(_AP_JWK))
        )
        respx.get(_SELLER_JWKS_URL).mock(
            return_value=httpx.Response(200, json=_make_jwks(_SELLER_JWK))
        )
        keypair = generate_dpop_keypair("ES256")
        url = "https://api.example.com/r"
        proof = create_dpop_proof(keypair, {"htm": "GET", "htu": url})
        quote_token = _make_quote_token()
        payment_token = _make_payment_token(
            quote_token=quote_token, cnf_jkt=extract_dpop_thumbprint(proof)
        )

        result = AgentPayFacilitatorClient().verify(
            payment_token,
            quote_token,
            _DEFAULT_REQUIREMENTS,
            verify_options={"dpop_proof": proof, "method": "get", "url": url},
        )

        assert result.is_valid is True
