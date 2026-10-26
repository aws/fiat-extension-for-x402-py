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
import json
import threading
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
# cached for a minute, so a revoked service key stops being accepted within a
# minute, and a token naming a key the cache lacks refetches at most every 30
# seconds: a flood of forged tokens costs at most one fetch per interval.
_SELLER_KEY_CACHE_TTL_SECONDS = 3600
_SERVICE_JWKS_CACHE_TTL_SECONDS = 60
_SERVICE_JWKS_MIN_REFETCH_SECONDS = 30
# A JWKS holds a handful of public keys; anything larger is refused.
_MAX_JWKS_BYTES = 64 * 1024
_JWKS_FETCH_TIMEOUT_SECONDS = 10

# Quote claims the buyer's quote must share with the route's current quote:
# all but the per-quote iat, exp and jti, and the price, which is checked
# against the requirements.
_ROUTE_BOUND_QUOTE_CLAIMS = ("iss", "aud", "payTo", "settlement", "reference", "scheme", "network")
# Quote claims that, when present, must equal the requirements' field of the
# same name. A quote without them, from a signer that predates them, passes.
_REQUIREMENT_QUOTE_CLAIMS = ("scheme", "network")


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

    1. Before any network call, check the unverified payment token: its
       algorithm is allowed, it names a key (``kid``), its issuer is the
       service, it has not expired, and the quote token embedded in it equals
       the quote in the requirements (constant-time comparison).
    2. Verify the payment token's signature with the service's JWKS, which
       covers the claims checked in step 1. The token must carry a
       ``payment_id``.
    3. Verify the quote token's signature with the seller's key, which the
       seller configures; it is never discovered from the token.
    4. Check the payment token's audience is the quote's issuer, and the quote
       has not expired.
    5. Check the quote's price matches the requirements' amount and currency
       and, given the route's current quote, that the quote is for this route.

    Verification is stateless: a payment token is accepted again until it or
    its quote expires. Record each ``payment_id`` to accept a payment once; see
    ``docs/security.md``.

    DPoP binding (``cnf.jkt``) is checked by the seller, which sees the HTTP
    request; see
    :class:`~fiat_extension_x402.agentic_commerce.exact.ExactAgenticCommerceServerScheme`.

    :meth:`verify` blocks while it fetches keys, at most about once a minute.
    x402's ``x402Facilitator`` calls it on the event loop, so an async seller
    stalls for that fetch; run verification in a thread pool if that matters.

    :param seller_key_resolver: Where to find the seller's quote-signing key.
    :param payment_token_jwks_url: Base URL of the service's JWKS. Defaults to
        the production endpoint.
    :param jwks_request_headers: Extra headers sent when fetching the service's
        JWKS.
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
        # One client for every fetch, so connections are reused. Redirects are
        # not followed, so the request headers never reach another host.
        self._http = httpx.Client(timeout=_JWKS_FETCH_TIMEOUT_SECONDS, follow_redirects=False)
        # The service JWKS and when it was fetched, and when a fetch was last tried.
        self._service_jwks: tuple[dict[str, Any], float] | None = None
        self._service_jwks_attempted_at: float | None = None
        # Held while fetching, so concurrent verifications share one fetch.
        self._service_jwks_lock = threading.Lock()

    def verify(
        self,
        payment_token: str,
        requirements: dict[str, Any],
        *,
        route_quote_token: str | None = None,
    ) -> VerificationResult:
        """Verify a payment token.

        :param payment_token: The payment token JWT.
        :param requirements: The requirements the payment claims to satisfy, with
            wire field names (``amount``, ``asset``, ``extra.quoteToken``, and
            optionally ``scheme`` and ``network``). A quote carrying ``scheme`` or
            ``network`` must match them.
        :param route_quote_token: The quote the seller currently signs for the
            route (the server's own ``extra.quoteToken``). When given, the paid
            quote must match it on ``iss``, ``aud``, ``payTo``, ``settlement``,
            ``reference``, ``scheme`` and ``network``, so a quote for another route, product or seller
            sharing the signing key is refused. The ``exact`` facilitator scheme
            always passes it.
        :returns: The verification outcome. Never raises for an invalid payment.
        """
        expected_quote_token = (requirements.get("extra") or {}).get("quoteToken")
        if not expected_quote_token:
            return _invalid("invalid_quote", "Missing quoteToken in payment requirements")

        # Cheap checks on the unverified token first, so a forged or stale token
        # is refused without a network call. The signature, verified next,
        # covers the same claims, so they need no second check.
        try:
            kid = _unverified_header_kid(payment_token)
            unverified_claims = jwt.decode(payment_token, options={"verify_signature": False})
        except Exception as exc:  # noqa: BLE001 - reported as an invalid payment
            return _invalid("invalid_payment", f"Payment token signature invalid: {exc}")
        refused = self._check_payment_claims(unverified_claims, str(expected_quote_token))
        if refused is not None:
            return refused

        try:
            payment_claims = _verify_with_jwks(payment_token, self._service_jwks_for(kid))
        except Exception as exc:  # noqa: BLE001 - reported as an invalid payment
            return _invalid("invalid_payment", f"Payment token signature invalid: {exc}")
        payment_id = payment_claims.get("payment_id")
        if not isinstance(payment_id, str) or not payment_id:
            return _invalid("invalid_payment", "Missing payment_id in payment token")
        quote_token: str = payment_claims["quote_token"]

        now = int(time.time())
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

        for name in _REQUIREMENT_QUOTE_CLAIMS:
            if name in quote_claims and quote_claims[name] != requirements.get(name):
                return _invalid("invalid_quote", "Quote is for a different scheme or network")

        if route_quote_token is not None:
            try:
                # The route's quote is the seller's own, so it is not verified.
                route_claims = jwt.decode(route_quote_token, options={"verify_signature": False})
            except jwt.PyJWTError as exc:
                return _invalid("invalid_quote", f"Route quote token is malformed: {exc}")
            if any(
                quote_claims.get(name) != route_claims.get(name)
                for name in _ROUTE_BOUND_QUOTE_CLAIMS
            ):
                return _invalid("invalid_quote", "Quote does not match this route")

        return VerificationResult(
            is_valid=True,
            payer=payment_claims.get("sub"),
            payment_id=payment_id,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_payment_claims(
        self, claims: dict[str, Any], expected_quote_token: str
    ) -> VerificationResult | None:
        """Refuse claims with another issuer, a passed expiry, or another quote."""
        if claims.get("iss") != self._payment_token_issuer:
            return _invalid("invalid_payment", "Payment token issuer is not the payment service")
        exp = claims.get("exp")
        if not isinstance(exp, int) or exp < int(time.time()):
            return _invalid("payment_expired", "Payment token expired")
        quote_token = claims.get("quote_token")
        if not isinstance(quote_token, str) or not quote_token:
            return _invalid("invalid_quote", "Missing quote token in payment token")
        if not secure_compare(quote_token, expected_quote_token):
            return _invalid("invalid_quote", "Payment token was issued for a different quote")
        return None

    def _service_jwks_for(self, kid: str) -> dict[str, Any]:
        """The service's JWKS, fetched when stale or when it lacks ``kid``.

        A fetch is tried at most every 30 seconds, and concurrent callers share
        it. Raises when no fresh JWKS is at hand.
        """
        with self._service_jwks_lock:
            now = time.time()
            cached = self._service_jwks
            fresh = cached is not None and now - cached[1] < _SERVICE_JWKS_CACHE_TTL_SECONDS
            wanted = cached is None or not fresh or not _has_kid(cached[0], kid)
            attempted = self._service_jwks_attempted_at
            may_fetch = attempted is None or now - attempted >= _SERVICE_JWKS_MIN_REFETCH_SECONDS
            if wanted and may_fetch:
                self._service_jwks_attempted_at = now
                jwks = self._fetch_jwks(self._payment_token_jwks_url, self._jwks_request_headers)
                self._service_jwks = (jwks, now)
                return jwks
            if cached is None or not fresh:
                raise ValidationError("Payment service JWKS unavailable; retrying shortly")
            return cached[0]

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

    def _fetch_jwks(self, url: str, headers: dict[str, str]) -> dict[str, Any]:
        with self._http.stream("GET", url, headers=headers) as response:
            if response.status_code != 200:
                raise ValidationError(
                    f"Failed to fetch JWKS from {url}: HTTP {response.status_code}"
                )
            body = bytearray()
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > _MAX_JWKS_BYTES:
                    raise ValidationError(f"JWKS from {url} exceeds {_MAX_JWKS_BYTES} bytes")
        jwks = json.loads(body)
        if not isinstance(jwks, dict):
            raise ValidationError(f"JWKS from {url} is not a JSON object")
        return jwks


def _unverified_header_kid(token: str) -> str:
    """Check the token's unverified header: an allowed algorithm and a key id."""
    header = jwt.get_unverified_header(token)
    alg = header.get("alg", "")
    if alg not in ALLOWED_ALGORITHMS:
        raise ValidationError(f"Algorithm not allowed: {alg}")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise ValidationError("Payment token names no key (kid)")
    return kid


def _has_kid(jwks: dict[str, Any], kid: str) -> bool:
    keys = jwks.get("keys")
    return isinstance(keys, list) and any(
        isinstance(key, dict) and key.get("kid") == kid for key in keys
    )


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
            key = jwt.PyJWK.from_dict(key_data).key
        except jwt.PyJWTError:
            # PyJWT's key-import errors can include the whole JWK, private
            # members and all, so name the key by its kid instead.
            key_kid = key_data.get("kid")
            label = f"JWK {key_kid}" if isinstance(key_kid, str) else "JWK"
            last_error = ValidationError(f"{label}: invalid key material")
            continue
        try:
            return _verify_with_key(token, key)
        except jwt.PyJWTError as exc:
            last_error = exc
    raise last_error


__all__ = ["AgenticCommerceVerifier", "VerificationResult"]
