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

import time
from typing import Any, Optional

import httpx
import jwt

from fiat_extension_x402.constants import (
    AGENT_PAY_JWKS_ACCESS_KEY,
    AGENT_PAY_JWKS_BASE_URL,
    WELL_KNOWN_JWKS_PATH,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.facilitator.types import SettleResponse, VerifyResponse
from fiat_extension_x402.security import ALLOWED_ALGORITHMS as _ALLOWED_ALGORITHMS
from fiat_extension_x402.security import secure_compare as _secure_compare

# Seller JWKS cache TTL (1 hour). Agent Pay's own keys are always fetched fresh
# (their JWKS endpoint enforces Cache-Control: no-store); only seller keys are cached.
_JWKS_CACHE_TTL_SECONDS = 3600


class AgentPayFacilitatorClient:
    """Facilitator client that verifies and settles Agent Pay payments.

    Verification steps:

    1. Fetch Agent Pay's JWKS and verify the payment token signature.
    2. Check payment token expiry.
    3. Extract the ``quote_token`` from the payment token claims.
    4. Verify the quote token matches the expected quote token from the
       payment requirements (constant-time comparison).
    5. Verify the quote token signature using the seller's JWKS.
    6. Verify amounts match between quote token and requirements.
    7. Return the verification result.

    Settlement returns success immediately because Agent Pay auto-captures
    during payment creation.

    :param jwks_base_url: Base URL for Agent Pay's JWKS endpoint. Defaults to
        the production CDN.
    """

    def __init__(
        self,
        *,
        jwks_base_url: Optional[str] = None,
    ) -> None:
        base = (jwks_base_url or AGENT_PAY_JWKS_BASE_URL).rstrip("/")
        self._jwks_url = f"{base}{WELL_KNOWN_JWKS_PATH}"
        # Seller JWKS cache: url -> (jwks, fetched_at). Agent Pay keys are not cached.
        self._seller_jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}

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
                    invalid_reason="expired",
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
                    invalid_reason="invalid_payment",
                    invalid_message="Missing quote token in payment JWT",
                )

            # 4. Verify quote token matches expected (constant-time comparison).
            if not _secure_compare(quote_token, expected_quote_token):
                return VerifyResponse(
                    is_valid=False,
                    invalid_reason="invalid_payment",
                    invalid_message="Quote token mismatch",
                )

            # 5. Decode the quote token and verify its signature using the seller's JWKS.
            quote_claims = self._decode_without_verification(quote_token)
            issuer = quote_claims.get("iss", "")
            seller_jwks_url = f"{issuer.rstrip('/')}{WELL_KNOWN_JWKS_PATH}"
            seller_jwks = self._fetch_jwks(seller_jwks_url, use_access_header=False)
            self._verify_token(quote_token, seller_jwks)

            # 6. Verify amounts match.
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

            # 7. DPoP verification. When the payment token is DPoP-bound (carries
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
                        invalid_reason="invalid_dpop",
                        invalid_message="DPoP thumbprint does not match cnf.jkt",
                    )

                dpop_options: dict[str, Any] = {}
                if "method" in opts:
                    dpop_options["htm"] = opts["method"]
                if "url" in opts:
                    dpop_options["htu"] = opts["url"]
                verify_dpop_proof(dpop_proof, dpop_options)

            # 8. Success.
            return VerifyResponse(is_valid=True, payer=payment_claims.get("sub"))

        except Exception as exc:  # noqa: BLE001 - catch-all matches reference behavior
            return VerifyResponse(
                is_valid=False,
                invalid_reason="verification_error",
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
        except Exception as exc:  # noqa: BLE001 - normalize unexpected failures
            raise ValidationError(f"Token verification failed: {exc}") from exc

        return claims

    @staticmethod
    def _decode_without_verification(token: str) -> dict[str, Any]:
        """Decode a JWT without signature verification."""
        return jwt.decode(token, options={"verify_signature": False})


__all__ = ["AgentPayFacilitatorClient"]
