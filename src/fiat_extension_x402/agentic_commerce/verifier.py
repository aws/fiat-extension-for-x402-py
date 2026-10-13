# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Payment token verification.

A buyer pays for a request by presenting a payment token: a JWT issued and
signed by the AWS Marketplace Agentic Commerce service that embeds the quote
token the seller signed. Verification is cryptographic and needs no call to the
service other than fetching its public keys.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

from fiat_extension_x402.agentic_commerce.keys import (
    JwksSellerKeyResolver,
    KmsSellerKeyResolver,
    SellerKeyResolver,
    StaticSellerKeyResolver,
)
from fiat_extension_x402.constants import (
    DEFAULT_PAYMENT_TOKEN_JWKS_BASE_URL,
    PAYMENT_TOKEN_ISSUER,
    WELL_KNOWN_JWKS_PATH,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.security import ALLOWED_ALGORITHMS, secure_compare

# Seller keys (JWKS or KMS) are cached for an hour. The service's own keys are
# fetched on every verification: its JWKS endpoint sends Cache-Control: no-store
# so that a revoked key stops being accepted immediately.
_SELLER_KEY_CACHE_TTL_SECONDS = 3600


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying a payment token.

    :param is_valid: Whether the payment is valid.
    :param invalid_reason: Machine-readable reason when invalid.
    :param invalid_message: Human-readable detail when invalid.
    :param payer: The buyer identifier (``sub`` claim), when valid.
    :param payment_id: The payment identifier (``payment_id`` claim), when valid.
    """

    is_valid: bool
    invalid_reason: str | None = None
    invalid_message: str | None = None
    payer: str | None = None
    payment_id: str | None = None


def _invalid(reason: str, message: str) -> VerificationResult:
    return VerificationResult(is_valid=False, invalid_reason=reason, invalid_message=message)


class AgenticCommerceVerifier:
    """Verifies payment tokens against the requirements they claim to satisfy.

    Verification steps:

    1. Verify the payment token's signature with the service's JWKS.
    2. Check its issuer is the service and it has not expired.
    3. Check the quote token embedded in it equals the quote in the
       requirements (constant-time comparison).
    4. Verify the quote token's signature with the seller's key, which the
       seller configures; it is never discovered from the token.
    5. Check the payment token's audience is the quote's issuer, and the quote
       has not expired.
    6. Check the quote's price matches the requirements' amount and currency.

    DPoP binding (``cnf.jkt``) is checked by the seller, which sees the HTTP
    request; see
    :class:`~fiat_extension_x402.agentic_commerce.exact.ExactAgenticCommerceServerScheme`.

    :param seller_key_resolver: Where to find the seller's quote-signing key.
    :param payment_token_jwks_url: Base URL of the service's JWKS. Defaults to
        the production endpoint.
    :param jwks_request_headers: Extra headers sent when fetching the service's
        JWKS. The production JWKS needs none.
    :param payment_token_issuer: Expected ``iss`` of payment tokens.
    """

    def __init__(
        self,
        *,
        seller_key_resolver: SellerKeyResolver,
        payment_token_jwks_url: str | None = None,
        jwks_request_headers: dict[str, str] | None = None,
        payment_token_issuer: str = PAYMENT_TOKEN_ISSUER,
    ) -> None:
        base = (payment_token_jwks_url or DEFAULT_PAYMENT_TOKEN_JWKS_BASE_URL).rstrip("/")
        self._payment_token_jwks_url = f"{base}{WELL_KNOWN_JWKS_PATH}"
        self._jwks_request_headers = dict(jwks_request_headers or {})
        self._payment_token_issuer = payment_token_issuer
        self._seller_key_resolver = seller_key_resolver
        self._seller_key_cache: dict[str, tuple[Any, float]] = {}

    def verify(self, payment_token: str, requirements: dict[str, Any]) -> VerificationResult:
        """Verify a payment token.

        :param payment_token: The payment token JWT.
        :param requirements: The requirements the payment claims to satisfy, with
            wire field names (``amount``, ``asset``, ``extra.quoteToken``).
        :returns: The verification outcome. Never raises for an invalid payment.
        """
        expected_quote_token = (requirements.get("extra") or {}).get("quoteToken")
        if not expected_quote_token:
            return _invalid("invalid_quote", "Missing quoteToken in payment requirements")

        try:
            payment_jwks = self._fetch_jwks(
                self._payment_token_jwks_url, self._jwks_request_headers
            )
            payment_claims = _verify_with_jwks(payment_token, payment_jwks)
        except Exception as exc:  # noqa: BLE001 - reported as an invalid payment
            return _invalid("invalid_payment", f"Payment token signature invalid: {exc}")

        now = int(time.time())
        if payment_claims.get("iss") != self._payment_token_issuer:
            return _invalid("invalid_payment", "Payment token issuer is not the payment service")
        exp = payment_claims.get("exp")
        if not isinstance(exp, int) or exp < now:
            return _invalid("payment_expired", "Payment token expired")

        quote_token = payment_claims.get("quote_token")
        if not isinstance(quote_token, str) or not quote_token:
            return _invalid("invalid_quote", "Missing quote token in payment token")
        if not secure_compare(quote_token, str(expected_quote_token)):
            return _invalid("invalid_quote", "Payment token was issued for a different quote")

        try:
            quote_claims = self._verify_quote(quote_token)
        except Exception as exc:  # noqa: BLE001 - reported as an invalid quote
            return _invalid("invalid_quote", f"Quote token signature invalid: {exc}")

        if payment_claims.get("aud") != quote_claims.get("iss"):
            return _invalid("invalid_payment", "Payment token audience is not the quote issuer")
        quote_exp = quote_claims.get("exp")
        if not isinstance(quote_exp, int) or quote_exp < now:
            return _invalid("quote_expired", "Quote token expired")

        price = quote_claims.get("price")
        currency = str(requirements.get("asset", "")).replace("iso4217:", "")
        if (
            not isinstance(price, dict)
            or price.get("amount") != requirements.get("amount")
            or price.get("currency") != currency
        ):
            return _invalid("invalid_payment", "Amount or currency mismatch")

        return VerificationResult(
            is_valid=True,
            payer=payment_claims.get("sub"),
            payment_id=payment_claims.get("payment_id"),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _verify_quote(self, quote_token: str) -> dict[str, Any]:
        resolver = self._seller_key_resolver
        if isinstance(resolver, KmsSellerKeyResolver):
            return _verify_with_key(quote_token, self._kms_public_key(resolver))
        if isinstance(resolver, StaticSellerKeyResolver):
            return _verify_with_jwks(quote_token, {"keys": [resolver.public_jwk]})
        if isinstance(resolver, JwksSellerKeyResolver):
            url = f"{resolver.jwks_url.rstrip('/')}{WELL_KNOWN_JWKS_PATH}"
            return _verify_with_jwks(
                quote_token, self._cached(url, lambda: self._fetch_jwks(url, {}))
            )
        raise ValidationError("A seller key resolver is required to verify quote tokens")

    def _cached(self, key: str, load: Any) -> Any:
        hit = self._seller_key_cache.get(key)
        now = time.time()
        if hit is not None and now - hit[1] < _SELLER_KEY_CACHE_TTL_SECONDS:
            return hit[0]
        value = load()
        self._seller_key_cache[key] = (value, now)
        return value

    def _kms_public_key(self, resolver: KmsSellerKeyResolver) -> str:
        def load() -> str:
            client = resolver.kms_client
            if client is None:
                # Imported lazily so the KMS path costs nothing when unused.
                import boto3  # type: ignore[import-untyped]

                kwargs: dict[str, Any] = {"region_name": resolver.region}
                if resolver.credentials is not None:
                    creds = resolver.credentials()
                    kwargs.update(
                        aws_access_key_id=getattr(creds, "access_key", None),
                        aws_secret_access_key=getattr(creds, "secret_key", None),
                        aws_session_token=getattr(creds, "token", None),
                    )
                client = boto3.client("kms", **kwargs)
            der = client.get_public_key(KeyId=resolver.kms_key_arn).get("PublicKey")
            if not der:
                raise ValidationError("KMS GetPublicKey returned no key material")
            body = base64.b64encode(der).decode()
            return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----"

        pem: str = self._cached(f"kms:{resolver.kms_key_arn}", load)
        return pem

    @staticmethod
    def _fetch_jwks(url: str, headers: dict[str, str]) -> dict[str, Any]:
        with httpx.Client(timeout=10) as client:
            response = client.get(url, headers=headers)
        if response.status_code != 200:
            raise ValidationError(f"Failed to fetch JWKS from {url}: HTTP {response.status_code}")
        jwks: dict[str, Any] = response.json()
        return jwks


def _verify_with_key(token: str, public_key: Any) -> dict[str, Any]:
    alg = jwt.get_unverified_header(token).get("alg", "")
    if alg not in ALLOWED_ALGORITHMS:
        raise ValidationError(f"Algorithm not allowed: {alg}")
    claims: dict[str, Any] = jwt.decode(
        token,
        public_key,
        algorithms=ALLOWED_ALGORITHMS,
        # Expiry and audience are checked by the caller.
        options={"verify_exp": False, "verify_aud": False},
    )
    return claims


def _verify_with_jwks(token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    """Verify with the key named by ``kid``; without a ``kid``, with any key in the set."""
    kid = jwt.get_unverified_header(token).get("kid")
    candidates = [k for k in jwks.get("keys", []) if kid is None or k.get("kid") == kid]
    if not candidates:
        raise ValidationError("No matching key found in JWKS")
    last_error: Exception = ValidationError("No matching key found in JWKS")
    for key_data in candidates:
        try:
            return _verify_with_key(token, jwt.PyJWK.from_dict(key_data).key)
        except jwt.PyJWTError as exc:
            last_error = exc
    raise last_error


__all__ = ["AgenticCommerceVerifier", "VerificationResult"]
