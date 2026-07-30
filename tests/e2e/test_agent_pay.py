# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests against a live Agent Pay endpoint.

These tests exercise the full buyer -> Agent Pay -> seller flow against the real
service. They are gated behind the ``e2e`` marker and the environment-driven
fixtures in ``conftest.py`` — running ``pytest`` without ``-m e2e`` deselects them,
and they skip (never fail) when live credentials are not configured.

Two realities shape these tests:

* The reference test seller signs its quotes with a self-hosted key, so the
  happy-path quote is sourced from the seller's live HTTP 402 response (the
  authoritative, service-registered quote) rather than minted locally via KMS.
* The shared test seller/product is registered only in *prod*. The
  ``agent_pay_environment_ready`` fixture probes the target stage once; tests
  that require the service to *accept* a quote skip (do not fail) on a stage
  that does not recognise the test seller.

Test cases follow the ticket's TC-1..TC-7:

* TC-1 — happy path full payment flow
* TC-2 — idempotency via client_token
* TC-3 — quote validation errors (negative cases)
* TC-4 — DPoP binding
* TC-5 — payment JWT verification (seller side)
* TC-6 — settle is a no-op
* TC-7 — GetAgentPayment / ListAgentPayments
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Callable

import pytest

pytestmark = pytest.mark.e2e


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------


# Shared Agent Pay reference test product (settlement target).
_TEST_PRODUCT_ID = "prod-owriuwojln3d4"

QuoteSource = Callable[[], "tuple[dict[str, Any], str]"]


async def _sign_quote(
    seller_signer: Any,
    *,
    amount: str = "0.05",
    currency: str = "USD",
    iat: int | None = None,
    exp: int | None = None,
    omit_iss: bool = False,
) -> str:
    """Sign a quote token directly via the seller KMS signer (for negative cases).

    Used only to forge quotes with bad claims (expired, missing issuer). The
    resulting token is signed by the seller KMS key and rejected by the service;
    the negative tests assert the rejection, not the specific reason.
    """
    now = int(time.time())
    payload: dict[str, Any] = {
        "aud": "aws:marketplace",
        "iat": iat if iat is not None else now,
        "exp": exp if exp is not None else now + 300,
        "jti": str(uuid.uuid4()),
        "price": {"amount": amount, "currency": currency},
        "payTo": "seller-e2e",
        "reference": "E2E",
        "settlement": {"product_id": _TEST_PRODUCT_ID},
    }
    if not omit_iss:
        payload["iss"] = seller_signer.get_service_url()
    token: str = await seller_signer.sign_quote(payload)
    return token


# ----------------------------------------------------------------------------
# TC-1 — Happy path
# ----------------------------------------------------------------------------


class TestTC1HappyPath:
    @pytest.mark.usefixtures("agent_pay_environment_ready")
    async def test_full_payment_flow(
        self,
        buyer_client: Any,
        quote_source: QuoteSource,
        facilitator: Any,
    ) -> None:
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        requirements, quote_token = quote_source()

        # Buyer creates the payment against the service.
        response = buyer_client.create_payment(
            CreateAgentPaymentRequest(quote_token=quote_token, client_token=str(uuid.uuid4()))
        )
        assert response.payment_id.startswith("awsmp-")
        assert response.payment_token

        # Seller verifies the resulting payment token against Agent Pay's JWKS,
        # cross-checking against the real quote's requirements (amount/currency).
        verify = facilitator.verify(response.payment_token, quote_token, requirements)
        assert verify.is_valid is True
        # NOTE: prod payment tokens carry aud/payment_id but no `sub`, so `payer`
        # is None here by design, not a bug. Do not assert truthy.

        # Settle is a no-op that reports success (auto-capture).
        settle = facilitator.settle(payment_id=response.payment_id, network="aws:base")
        assert settle.success is True
        assert settle.transaction == response.payment_id


# ----------------------------------------------------------------------------
# TC-2 — Idempotency
# ----------------------------------------------------------------------------


class TestTC2Idempotency:
    @pytest.mark.usefixtures("agent_pay_environment_ready")
    async def test_same_client_token_returns_same_payment(
        self,
        buyer_client: Any,
        quote_source: QuoteSource,
    ) -> None:
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        _, quote_token = quote_source()
        client_token = str(uuid.uuid4())

        first = buyer_client.create_payment(
            CreateAgentPaymentRequest(quote_token=quote_token, client_token=client_token)
        )
        second = buyer_client.create_payment(
            CreateAgentPaymentRequest(quote_token=quote_token, client_token=client_token)
        )
        assert first.payment_id == second.payment_id

    @pytest.mark.usefixtures("agent_pay_environment_ready")
    async def test_different_client_token_returns_different_payment(
        self,
        buyer_client: Any,
        quote_source: QuoteSource,
    ) -> None:
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        _, quote1 = quote_source()
        _, quote2 = quote_source()
        first = buyer_client.create_payment(
            CreateAgentPaymentRequest(quote_token=quote1, client_token=str(uuid.uuid4()))
        )
        second = buyer_client.create_payment(
            CreateAgentPaymentRequest(quote_token=quote2, client_token=str(uuid.uuid4()))
        )
        assert first.payment_id != second.payment_id


# ----------------------------------------------------------------------------
# TC-3 — Quote validation errors (negative cases)
# ----------------------------------------------------------------------------


class TestTC3QuoteValidationErrors:
    async def test_tampered_quote_signature_rejected(
        self, buyer_client: Any, quote_source: QuoteSource
    ) -> None:
        from fiat_extension_x402.exceptions import ValidationError
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        _, quote_token = quote_source()
        # Corrupt the signature segment of an otherwise-registered quote.
        tampered = quote_token[:-6] + "XXXXXX"
        with pytest.raises(ValidationError):
            buyer_client.create_payment(
                CreateAgentPaymentRequest(quote_token=tampered, client_token=str(uuid.uuid4()))
            )

    async def test_expired_quote_rejected(self, buyer_client: Any, seller_signer: Any) -> None:
        from fiat_extension_x402.exceptions import ValidationError
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        past = int(time.time()) - 600
        expired_quote = await _sign_quote(seller_signer, iat=past - 300, exp=past)
        with pytest.raises(ValidationError):
            buyer_client.create_payment(
                CreateAgentPaymentRequest(quote_token=expired_quote, client_token=str(uuid.uuid4()))
            )

    async def test_quote_missing_issuer_rejected(
        self, buyer_client: Any, seller_signer: Any
    ) -> None:
        from fiat_extension_x402.exceptions import ValidationError
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        no_iss_quote = await _sign_quote(seller_signer, omit_iss=True)
        with pytest.raises(ValidationError):
            buyer_client.create_payment(
                CreateAgentPaymentRequest(quote_token=no_iss_quote, client_token=str(uuid.uuid4()))
            )

    async def test_malformed_quote_rejected(self, buyer_client: Any) -> None:
        from fiat_extension_x402.exceptions import ValidationError
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        with pytest.raises(ValidationError):
            buyer_client.create_payment(
                CreateAgentPaymentRequest(quote_token="not-a-jwt", client_token=str(uuid.uuid4()))
            )

    @pytest.mark.usefixtures("agent_pay_environment_ready")
    async def test_amount_mismatch_rejected_by_facilitator(
        self,
        buyer_client: Any,
        quote_source: QuoteSource,
        facilitator: Any,
    ) -> None:
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        requirements, quote_token = quote_source()
        response = buyer_client.create_payment(
            CreateAgentPaymentRequest(quote_token=quote_token, client_token=str(uuid.uuid4()))
        )
        # Verify against requirements demanding a different amount than the quote.
        mismatched = {**requirements, "amount": "9999.99"}
        verify = facilitator.verify(response.payment_token, quote_token, mismatched)
        assert verify.is_valid is False
        assert verify.invalid_reason == "invalid_payment"


# ----------------------------------------------------------------------------
# TC-3b — Empty-issuer guard (client-side, regression for the Lukka incident)
# ----------------------------------------------------------------------------


class TestTC3bEmptyIssuerGuard:
    """Regression for a partner integration that emitted quote tokens with an
    empty ``iss`` claim, which Agent Pay rejects with
    ``400 ... Missing or empty: [iss]``.

    Root cause was a KMS signer configured with an empty ``service_url`` (the
    field that becomes the quote token's ``iss``). The SDK now rejects this at
    the source — signer construction and quote signing both refuse an empty
    issuer — so a malformed token is never minted or sent to the service.

    The two rejection tests are purely client-side (they assert the guard fires
    before any signing), so they run on every stage regardless of test-seller
    registration. The final happy-path test does exercise live KMS ``Sign`` via
    the real ``seller_signer`` fixture — it needs the seller KMS key/credentials
    (``AGENTPAY_SELLER_*``) to be resolvable, which the e2e fixtures already
    require.
    """

    def test_kms_signer_rejects_empty_service_url(self, agent_pay_config: Any) -> None:
        """Building the seller's real KMS signer with an empty service_url fails."""
        import boto3  # type: ignore[import-untyped]

        from fiat_extension_x402 import KmsSignerConfig, create_kms_signer
        from fiat_extension_x402.signers.kms import SigningError

        if agent_pay_config.seller_profile:
            session = boto3.Session(profile_name=agent_pay_config.seller_profile)
        else:
            session = boto3.Session()
        kms_client = session.client("kms", region_name=agent_pay_config.seller_region)

        with pytest.raises(SigningError, match="service_url is required"):
            create_kms_signer(
                KmsSignerConfig(
                    key_arn=agent_pay_config.seller_kms_key_arn,
                    region=agent_pay_config.seller_region,
                    service_url="",
                    _kms_client=kms_client,
                )
            )

    async def test_enhance_requirements_rejects_empty_issuer(self, seller_signer: Any) -> None:
        """``enhance_payment_requirements`` refuses to sign when the issuer is empty.

        The real seller KMS signer is wrapped so ``get_service_url()`` returns an
        empty string — reproducing the incident config — and the scheme rejects it
        before signing, so no empty-``iss`` token reaches the service.
        """
        from fiat_extension_x402 import enhance_payment_requirements
        from fiat_extension_x402.exceptions import ValidationError

        class _EmptyIssuerSigner:
            def __init__(self, delegate: Any) -> None:
                self._delegate = delegate

            async def sign_quote(self, payload: dict[str, Any]) -> str:
                token: str = await self._delegate.sign_quote(payload)
                return token

            def get_public_key(self) -> object:
                return self._delegate.get_public_key()

            def get_service_url(self) -> str:
                return ""

        base_requirements: dict[str, Any] = {
            "scheme": "agent-pay",
            "network": "aws:base",
            "payTo": "seller",
            "amount": "0.001",
            "asset": "iso4217:USD",
            "extra": {"settlement": {"product_id": _TEST_PRODUCT_ID}},
        }
        with pytest.raises(ValidationError, match="issuer"):
            await enhance_payment_requirements(base_requirements, _EmptyIssuerSigner(seller_signer))

    async def test_valid_issuer_still_produces_nonempty_iss(self, seller_signer: Any) -> None:
        """A correctly-configured seller signer still mints a token with a real ``iss``.

        Confirms the guard is not over-eager: the happy path (non-empty
        ``service_url``) yields a quote token whose ``iss`` matches the configured
        service URL. Unlike the two rejection tests above, this one signs via live
        KMS through the real ``seller_signer`` fixture, so it needs the seller KMS
        key/credentials to be resolvable.
        """
        from fiat_extension_x402 import decode_quote_token, enhance_payment_requirements

        base_requirements: dict[str, Any] = {
            "scheme": "agent-pay",
            "network": "aws:base",
            "payTo": "seller",
            "amount": "0.001",
            "asset": "iso4217:USD",
            "extra": {"settlement": {"product_id": _TEST_PRODUCT_ID}},
        }
        enhanced = await enhance_payment_requirements(base_requirements, seller_signer)
        quote_token = enhanced["extra"]["quoteToken"]
        claims = decode_quote_token(quote_token)
        assert claims["iss"] == seller_signer.get_service_url()
        assert claims["iss"]  # non-empty


# ----------------------------------------------------------------------------
# TC-4 — DPoP binding
# ----------------------------------------------------------------------------


class TestTC4DpopBinding:
    @pytest.mark.usefixtures("agent_pay_environment_ready")
    async def test_dpop_bound_payment_verifies_with_matching_proof(
        self,
        buyer_client: Any,
        quote_source: QuoteSource,
        facilitator: Any,
    ) -> None:
        from fiat_extension_x402 import (
            create_dpop_proof,
            extract_dpop_thumbprint,
            generate_dpop_keypair,
            to_dpop_jwk,
        )
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        keypair = generate_dpop_keypair("ES256")
        requirements, quote_token = quote_source()

        response = buyer_client.create_payment(
            CreateAgentPaymentRequest(
                quote_token=quote_token,
                client_token=str(uuid.uuid4()),
                dpop_jwk=to_dpop_jwk(keypair),
            )
        )

        proof = create_dpop_proof(
            keypair, {"htm": "GET", "htu": "https://api.seller.example.com/resource"}
        )
        # The payment token's cnf.jkt (when present) must equal the proof thumbprint.
        assert extract_dpop_thumbprint(proof)

        verify = facilitator.verify(
            response.payment_token,
            quote_token,
            requirements,
            verify_options={
                "dpop_proof": proof,
                "method": "GET",
                "url": "https://api.seller.example.com/resource",
            },
        )
        assert verify.is_valid is True


# ----------------------------------------------------------------------------
# TC-5 — Payment JWT verification (seller side)
# ----------------------------------------------------------------------------


class TestTC5PaymentVerification:
    @pytest.mark.usefixtures("agent_pay_environment_ready")
    async def test_valid_payment_token_verifies(
        self,
        buyer_client: Any,
        quote_source: QuoteSource,
        facilitator: Any,
    ) -> None:
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        requirements, quote_token = quote_source()
        response = buyer_client.create_payment(
            CreateAgentPaymentRequest(quote_token=quote_token, client_token=str(uuid.uuid4()))
        )
        verify = facilitator.verify(response.payment_token, quote_token, requirements)
        assert verify.is_valid is True

    @pytest.mark.usefixtures("agent_pay_environment_ready")
    async def test_tampered_payment_token_rejected(
        self,
        buyer_client: Any,
        quote_source: QuoteSource,
        facilitator: Any,
    ) -> None:
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        requirements, quote_token = quote_source()
        response = buyer_client.create_payment(
            CreateAgentPaymentRequest(quote_token=quote_token, client_token=str(uuid.uuid4()))
        )
        tampered = response.payment_token[:-6] + "XXXXXX"
        verify = facilitator.verify(tampered, quote_token, requirements)
        assert verify.is_valid is False


# ----------------------------------------------------------------------------
# TC-6 — Settle is a no-op
# ----------------------------------------------------------------------------


class TestTC6SettleNoOp:
    def test_settle_returns_success_without_http(self, facilitator: Any) -> None:
        result = facilitator.settle(payment_id="awsmp-e2e-settle", network="aws:base")
        assert result.success is True
        assert result.transaction == "awsmp-e2e-settle"
        assert result.network == "aws:base"

    def test_settle_is_repeatable(self, facilitator: Any) -> None:
        first = facilitator.settle(payment_id="awsmp-repeat", network="aws:base")
        second = facilitator.settle(payment_id="awsmp-repeat", network="aws:base")
        assert first == second


# ----------------------------------------------------------------------------
# TC-7 — GetAgentPayment / ListAgentPayments
# ----------------------------------------------------------------------------


class TestTC7GetAndList:
    @pytest.mark.usefixtures("agent_pay_environment_ready")
    async def test_get_payment_returns_created_record(
        self,
        buyer_client: Any,
        quote_source: QuoteSource,
    ) -> None:
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        _, quote_token = quote_source()
        created = buyer_client.create_payment(
            CreateAgentPaymentRequest(quote_token=quote_token, client_token=str(uuid.uuid4()))
        )

        fetched = buyer_client.get_payment(created.payment_id)
        assert fetched.payment.payment_id == created.payment_id

    @pytest.mark.usefixtures("agent_pay_environment_ready")
    async def test_list_payments_includes_created(
        self,
        buyer_client: Any,
        quote_source: QuoteSource,
    ) -> None:
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        _, quote_token = quote_source()
        created = buyer_client.create_payment(
            CreateAgentPaymentRequest(quote_token=quote_token, client_token=str(uuid.uuid4()))
        )

        listed = buyer_client.list_payments({"maxResults": 25})
        payment_ids = {p.payment_id for p in listed.payments}
        assert created.payment_id in payment_ids
