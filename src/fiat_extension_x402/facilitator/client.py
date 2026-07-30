# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Agent Pay facilitator client — verifies payment tokens and settles payments.

In Agent Pay the provider IS the facilitator. Verification is cryptographic:
the payment token JWT is verified against Agent Pay's JWKS, and the embedded
quote token is compared to the expected quote token from the payment
requirements. Settlement is a no-op because Agent Pay auto-captures on
payment creation.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Optional, Union

import httpx
import jwt

from fiat_extension_x402.constants import (
    AGENT_PAY_JWKS_ACCESS_KEY,
    AGENT_PAY_JWKS_BASE_URL,
    DEFAULT_AGENT_PAY_BASE_URL,
    WELL_KNOWN_JWKS_PATH,
    WELL_KNOWN_X402_SUPPORTED_PATH,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.facilitator.types import SettleResponse, VerifyResponse
from fiat_extension_x402.security import ALLOWED_ALGORITHMS as _ALLOWED_ALGORITHMS
from fiat_extension_x402.security import secure_compare as _secure_compare

# Seller JWKS cache TTL (1 hour). Agent Pay's own keys are always fetched fresh
# (their JWKS endpoint enforces Cache-Control: no-store); only seller keys are cached.
_JWKS_CACHE_TTL_SECONDS = 3600


@dataclass(frozen=True)
class KmsSellerKeyResolver:
    """Resolve the seller's public key from KMS via ``kms:GetPublicKey``.

    :param kms_key_arn: ARN of the seller's signing key.
    :param region: Region hosting the key.
    :param credentials: Callable returning credentials for the KMS call. Omit to
        use the ambient boto3 credential chain.
    """

    kms_key_arn: str
    region: str
    credentials: Optional[Callable[[], Any]] = None


@dataclass(frozen=True)
class JwksSellerKeyResolver:
    """Resolve the seller's public key from an explicit JWKS base URL.

    :param jwks_url: Base URL. ``/.well-known/jwks.json`` is appended.
    """

    jwks_url: str


#: Strategy for locating the seller's quote-signing key. When omitted, the key is
#: discovered from the quote token's ``iss`` claim.
SellerKeyResolver = Union[KmsSellerKeyResolver, JwksSellerKeyResolver]


class AgentPayFacilitatorClient:
    """Facilitator client that verifies and settles Agent Pay payments.

    Verification steps:

    1. Fetch Agent Pay's JWKS and verify the payment token signature.
    2. Check payment token expiry.
    3. Extract the ``quote_token`` from the payment token claims.
    4. Verify the quote token matches the expected quote token from the
       payment requirements (constant-time comparison).
    5. Verify the quote token signature using the seller's JWKS.
    6. Check quote token expiry.
    7. Verify amounts match between quote token and requirements.
    8. Verify the DPoP binding when the payment token carries ``cnf.jkt``.
    9. Return the verification result.

    Settlement returns success immediately because Agent Pay auto-captures
    during payment creation.

    :param jwks_base_url: Base URL for Agent Pay's JWKS endpoint. Defaults to
        the production CDN.
    :param agent_pay_base_url: Base URL of the Agent Pay service, used by
        :meth:`get_supported`. Defaults to production.
    :param seller_key_resolver: How to locate the seller's quote-signing key.
        Omit to discover it from the quote token's ``iss`` claim.
    :param network_filter: When set, :meth:`get_supported` returns only kinds on
        these networks, so this facilitator cannot claim networks the integrator
        did not choose.
    """

    def __init__(
        self,
        *,
        jwks_base_url: Optional[str] = None,
        agent_pay_base_url: Optional[str] = None,
        seller_key_resolver: Optional[SellerKeyResolver] = None,
        network_filter: Optional[set[str]] = None,
    ) -> None:
        base = (jwks_base_url or AGENT_PAY_JWKS_BASE_URL).rstrip("/")
        self._jwks_url = f"{base}{WELL_KNOWN_JWKS_PATH}"
        self._agent_pay_base_url = (agent_pay_base_url or DEFAULT_AGENT_PAY_BASE_URL).rstrip("/")
        self._seller_key_resolver = seller_key_resolver
        self._network_filter = network_filter
        # Seller JWKS cache: url -> (jwks, fetched_at). Agent Pay keys are not cached.
        self._seller_jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}
        # KMS public-key cache: arn -> (pem, fetched_at).
        self._kms_key_cache: dict[str, tuple[str, float]] = {}

    def get_supported(self) -> dict[str, Any]:
        """Fetch the payment kinds Agent Pay supports.

        Maps to: GET ``{agent_pay_base_url}/.well-known/x402-supported``

        When ``network_filter`` is configured, kinds on other networks are
        dropped so this facilitator does not shadow another for networks the
        integrator did not opt into.

        :returns: The supported-kinds document.
        :raises ValidationError: if the request fails.
        """
        url = f"{self._agent_pay_base_url}{WELL_KNOWN_X402_SUPPORTED_PATH}"
        try:
            with httpx.Client() as client:
                response = client.get(url)
            if not 200 <= response.status_code < 300:
                raise ValidationError(
                    f"Failed to fetch supported kinds ({response.status_code}): "
                    f"{response.reason_phrase}"
                )
            supported: dict[str, Any] = response.json()
        except ValidationError:
            raise
        except Exception as exc:  # Normalize transport failures.
            raise ValidationError(f"Failed to fetch supported kinds: {exc}") from exc

        if self._network_filter is not None:
            kinds = supported.get("kinds")
            if isinstance(kinds, list):
                supported["kinds"] = [
                    k
                    for k in kinds
                    if isinstance(k, dict) and k.get("network") in self._network_filter
                ]
        return supported

    def verify(
        self,
        payment_token: str,
        expected_quote_token: str,
        payment_requirements: dict[str, Any],
        verify_options: Optional[dict[str, Any]] = None,
    ) -> VerifyResponse:
        """Verify an Agent Pay payment token.

        :param payment_token: The payment token JWT (signed by Agent Pay).
        :param expected_quote_token: The quote token from the payment
            requirements (``extra.quoteToken``). Used for matching.
        :param payment_requirements: The payment requirements being satisfied,
            used for amount/currency cross-checking.
        :returns: A :class:`VerifyResponse` indicating validity.
        """
        try:
            # 1. Fetch Agent Pay's JWKS and verify payment token signature.
            agent_pay_jwks = self._fetch_jwks(self._jwks_url, use_access_header=True)
            payment_claims = self._verify_token(payment_token, agent_pay_jwks)

            # 2. Check payment token expiry.
            now = int(time.time())
            exp = payment_claims.get("exp")
            if exp is not None and exp < now:
                return VerifyResponse(
                    is_valid=False,
                    invalid_reason="payment_expired",
                    invalid_message="Payment token expired",
                )

            # 3. Extract quote_token from payment token claims. Agent Pay puts it at
            #    the top level, with a fallback to payment_context for compatibility.
            quote_token: Optional[str] = payment_claims.get("quote_token")
            if quote_token is None:
                pc = payment_claims.get("payment_context")
                if isinstance(pc, dict):
                    quote_token = pc.get("quote_token")
            if not quote_token:
                return VerifyResponse(
                    is_valid=False,
                    invalid_reason="invalid_quote",
                    invalid_message="Missing quote token in payment JWT",
                )

            # 4. Verify quote token matches expected (constant-time comparison).
            if not _secure_compare(quote_token, expected_quote_token):
                return VerifyResponse(
                    is_valid=False,
                    invalid_reason="invalid_quote",
                    invalid_message="Quote token mismatch",
                )

            # 5. Decode the quote token and verify its signature with the seller's key.
            quote_claims = self._decode_without_verification(quote_token)
            # An issuer is only required when it is what locates the key; an
            # explicitly configured resolver supersedes it.
            issuer = quote_claims.get("iss", "")
            if not issuer and self._seller_key_resolver is None:
                return VerifyResponse(
                    is_valid=False,
                    invalid_reason="invalid_quote",
                    invalid_message="Quote token has no issuer",
                )
            self._verify_quote_signature(quote_token, issuer)

            # 6. Check quote token expiry. The signature check above runs with
            #    verify_exp disabled, so the quote's own window is enforced here.
            quote_exp = quote_claims.get("exp")
            if quote_exp is not None and quote_exp < now:
                return VerifyResponse(
                    is_valid=False,
                    invalid_reason="quote_expired",
                    invalid_message="Quote token expired",
                )

            # 7. Verify amounts match.
            price = quote_claims.get("price")
            if isinstance(price, list):
                price = price[0] if price else None
            req_currency = payment_requirements.get("asset", "").replace("iso4217:", "")
            if (
                not isinstance(price, dict)
                or price.get("amount") != payment_requirements.get("amount")
                or price.get("currency") != req_currency
            ):
                return VerifyResponse(
                    is_valid=False,
                    invalid_reason="invalid_payment",
                    invalid_message="Amount or currency mismatch",
                )

            # 8. DPoP verification. When the payment token is DPoP-bound (carries
            #    cnf.jkt), a matching proof is mandatory — a bound token cannot be
            #    accepted without one.
            cnf = payment_claims.get("cnf")
            if isinstance(cnf, dict) and "jkt" in cnf:
                from fiat_extension_x402.dpop.proof_verification import (
                    extract_dpop_thumbprint,
                    verify_dpop_proof,
                )

                opts = verify_options or {}
                dpop_proof = opts.get("dpop_proof")
                if not dpop_proof:
                    return VerifyResponse(
                        is_valid=False,
                        invalid_reason="dpop_required",
                        invalid_message="Payment token is DPoP-bound but no DPoP proof provided",
                    )

                thumbprint = extract_dpop_thumbprint(dpop_proof)
                if thumbprint != cnf["jkt"]:
                    return VerifyResponse(
                        is_valid=False,
                        invalid_reason="dpop_invalid",
                        invalid_message="DPoP thumbprint does not match cnf.jkt",
                    )

                # A proof without the request it is bound to would be checked
                # for signature and thumbprint but not for htm/htu, silently
                # dropping the request binding. Fail closed instead.
                method = opts.get("method")
                url = opts.get("url")
                if not method or not url:
                    return VerifyResponse(
                        is_valid=False,
                        invalid_reason="dpop_invalid",
                        invalid_message=(
                            "DPoP verification requires the request method and url "
                            "to check the proof's htm/htu binding"
                        ),
                    )
                # Compare the method case-insensitively; RFC 9449 htm is uppercase.
                verify_dpop_proof(dpop_proof, {"htm": str(method).upper(), "htu": url})

            # 9. Success.
            return VerifyResponse(is_valid=True, payer=payment_claims.get("sub"))

        except Exception as exc:  # noqa: BLE001 - catch-all matches reference behavior
            return VerifyResponse(
                is_valid=False,
                invalid_reason="verification_failed",
                invalid_message=str(exc) if str(exc) else "Verification failed",
            )

    def settle(
        self,
        *,
        payment_id: str,
        network: str,
    ) -> SettleResponse:
        """Settle an Agent Pay payment.

        Agent Pay auto-captures on creation. No HTTP call is needed —
        this returns success immediately.

        :param payment_id: The payment ID (``awsmp-{UUID}``).
        :param network: The network from the payment requirements.
        :returns: A :class:`SettleResponse` with ``success=True``.
        """
        return SettleResponse(success=True, transaction=payment_id, network=network)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _verify_quote_signature(self, quote_token: str, issuer: str) -> None:
        """Verify the quote token's signature with the seller's public key.

        Resolution order:

        1. An explicitly configured :class:`KmsSellerKeyResolver` or
           :class:`JwksSellerKeyResolver`.
        2. Otherwise, the JWKS at ``{iss}/.well-known/jwks.json``.

        :raises Exception: propagated to :meth:`verify`'s handler, which reports
            ``verification_failed``.
        """
        resolver = self._seller_key_resolver

        if isinstance(resolver, KmsSellerKeyResolver):
            self._verify_token_with_key(quote_token, self._resolve_kms_public_key(resolver))
            return

        if isinstance(resolver, JwksSellerKeyResolver):
            base = resolver.jwks_url.rstrip("/")
        else:
            base = issuer.rstrip("/")

        jwks = self._fetch_jwks(f"{base}{WELL_KNOWN_JWKS_PATH}", use_access_header=False)
        self._verify_token(quote_token, jwks)

    def _resolve_kms_public_key(self, resolver: KmsSellerKeyResolver) -> str:
        """Return the seller's KMS public key as a PEM, cached like seller JWKS."""
        cached = self._kms_key_cache.get(resolver.kms_key_arn)
        now = time.time()
        if cached is not None and now - cached[1] < _JWKS_CACHE_TTL_SECONDS:
            return cached[0]

        # Imported lazily so the KMS path costs nothing when unused.
        import boto3  # type: ignore[import-untyped]

        client_kwargs: dict[str, Any] = {"region_name": resolver.region}
        if resolver.credentials is not None:
            creds = resolver.credentials()
            client_kwargs.update(
                aws_access_key_id=getattr(creds, "access_key", None),
                aws_secret_access_key=getattr(creds, "secret_key", None),
                aws_session_token=getattr(creds, "token", None),
            )
        kms = boto3.client("kms", **client_kwargs)
        response = kms.get_public_key(KeyId=resolver.kms_key_arn)
        der = response.get("PublicKey")
        if not der:
            raise ValidationError("KMS GetPublicKey returned no key material")

        body = base64.b64encode(der).decode()
        pem = f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----"
        self._kms_key_cache[resolver.kms_key_arn] = (pem, now)
        return pem

    @staticmethod
    def _verify_token_with_key(token: str, public_key: Any) -> dict[str, Any]:
        """Verify a JWT against a single public key (the KMS resolver path)."""
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "")
        if alg not in _ALLOWED_ALGORITHMS:
            raise ValidationError(f"Algorithm not allowed: {alg}")
        claims: dict[str, Any] = jwt.decode(
            token,
            public_key,
            algorithms=_ALLOWED_ALGORITHMS,
            options={"verify_exp": False, "verify_aud": False},
        )
        return claims

    def _fetch_jwks(self, url: str, *, use_access_header: bool) -> dict[str, Any]:
        """Fetch a JWKS document from the given URL.

        Agent Pay's own keys (``use_access_header=True``) are always fetched
        fresh — their endpoint enforces no-store. Seller keys are cached with a
        one-hour TTL keyed by URL.

        :raises ValidationError: if the fetch fails.
        """
        if not use_access_header:
            cached = self._seller_jwks_cache.get(url)
            if cached is not None and (time.time() - cached[1]) < _JWKS_CACHE_TTL_SECONDS:
                return cached[0]

        headers: dict[str, str] = {}
        if use_access_header:
            headers["x-agentpay-key"] = AGENT_PAY_JWKS_ACCESS_KEY

        with httpx.Client() as client:
            response = client.get(url, headers=headers)

        if response.status_code != 200:
            raise ValidationError(f"Failed to fetch JWKS from {url}: {response.reason_phrase}")

        jwks: dict[str, Any] = response.json()

        if not use_access_header:
            self._seller_jwks_cache[url] = (jwks, time.time())

        return jwks

    @staticmethod
    def _verify_token(token: str, jwks_data: dict[str, Any]) -> dict[str, Any]:
        """Verify a JWT against a JWKS and return the decoded claims.

        Resolves the signing key from the JWKS by ``kid`` and verifies the
        signature with the algorithm allowlist.

        :raises ValidationError: if verification fails.
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            alg = unverified_header.get("alg")

            if alg not in _ALLOWED_ALGORITHMS:
                raise ValidationError(f"Algorithm not allowed: {alg}")

            # Find the matching key in the JWKS. Match by kid when the header
            # carries one; otherwise fall back to the first key.
            signing_key = None
            for key_data in jwks_data.get("keys", []):
                if kid is not None and key_data.get("kid") != kid:
                    continue
                # PyJWK handles all key types (EC, RSA, ...) via the JWK's kty.
                signing_key = jwt.PyJWK.from_dict(key_data).key
                break

            if signing_key is None:
                raise ValidationError("No matching key found in JWKS")

            # Verify signature. Disable exp check — we check it separately.
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key,
                algorithms=_ALLOWED_ALGORITHMS,
                options={"verify_exp": False, "verify_aud": False},
            )
        except ValidationError:
            raise
        except jwt.PyJWTError as exc:
            raise ValidationError(f"Token verification failed: {exc}") from exc
        except Exception as exc:  # Normalize unexpected failures.
            raise ValidationError(f"Token verification failed: {exc}") from exc

        return claims

    @staticmethod
    def _decode_without_verification(token: str) -> dict[str, Any]:
        """Decode a JWT without signature verification."""
        return jwt.decode(token, options={"verify_signature": False})


__all__ = [
    "AgentPayFacilitatorClient",
    "JwksSellerKeyResolver",
    "KmsSellerKeyResolver",
    "SellerKeyResolver",
]
