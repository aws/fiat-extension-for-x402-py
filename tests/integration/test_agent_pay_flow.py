# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""In-process Agent Pay integration tests.

Exercise the full buyer -> Agent Pay -> seller round-trip by wiring the SDK's
real components together with in-memory JWKS mocks (no network, no credentials).
This is the hermetic counterpart to the live ``tests/e2e`` suite.

Flow per test:
1. Seller builds enhanced requirements + signed quote (``enhance_payment_requirements``).
2. Mock Agent Pay issues a payment token embedding the quote.
3. Seller verifies the payment token (``AgentPayFacilitatorClient.verify``) against
   the mocked Agent Pay + seller JWKS endpoints.
4. Seller settles (no-op auto-capture).
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
import respx
from x402.schemas import PaymentPayload, PaymentRequired, PaymentRequirements

from fiat_extension_x402 import (
    AgentPayFacilitatorClient,
    InProcessFacilitatorClient,
)
from fiat_extension_x402.constants import AGENT_PAY_SENTINEL_PAY_TO
from fiat_extension_x402.exceptions import ValidationError


def _requirements_for(quote_requirements: dict[str, Any]) -> dict[str, Any]:
    """Map enhanced requirements to the facilitator's verify requirements."""
    return {
        "amount": quote_requirements["amount"],
        "asset": quote_requirements["asset"],
        "network": quote_requirements["network"],
    }


def _payment_required(enhanced_requirements: dict[str, Any]) -> PaymentRequired:
    """Wrap the seller's enhanced requirements in a 402 body for the buyer."""
    return PaymentRequired(
        x402_version=2,
        accepts=[PaymentRequirements.model_validate(enhanced_requirements)],
    )


class TestFullPaymentFlow:
    """The complete in-process buyer -> Agent Pay -> seller round-trip."""

    @respx.mock
    async def test_full_flow_succeeds(self, harness: Any) -> None:
        harness.mock_jwks(respx.mock)

        requirements, quote_token = await harness.build_quote(amount="0.15")
        # The enhanced requirements carry the sentinel payTo and the quote token.
        assert requirements["payTo"] == AGENT_PAY_SENTINEL_PAY_TO
        assert requirements["extra"]["quoteToken"] == quote_token

        payment_token = harness.issue_payment_token(quote_token, sub=harness.agent_pay_id)

        facilitator = AgentPayFacilitatorClient()
        result = facilitator.verify(payment_token, quote_token, _requirements_for(requirements))
        assert result.is_valid is True
        assert result.payer == harness.agent_pay_id

        settle = facilitator.settle(payment_id="awsmp-int-1", network="aws:base")
        assert settle.success is True
        assert settle.network == "aws:base"

    @respx.mock
    async def test_full_flow_via_in_process_facilitator(self, harness: Any) -> None:
        """The InProcessFacilitatorClient wrapper drives the same round-trip."""
        harness.mock_jwks(respx.mock)

        requirements, quote_token = await harness.build_quote()
        payment_token = harness.issue_payment_token(quote_token, sub=harness.agent_pay_id)

        facilitator = InProcessFacilitatorClient(AgentPayFacilitatorClient())
        result = facilitator.verify(payment_token, quote_token, _requirements_for(requirements))
        assert result.is_valid is True

        settle = facilitator.settle(payment_id="awsmp-int-2", network="aws:base")
        assert settle.success is True


class TestMultiNetworkFlow:
    """Network-aware round-trips: the same flow works across networks."""

    @respx.mock
    async def test_flow_on_aws_base(self, harness: Any) -> None:
        harness.mock_jwks(respx.mock)
        requirements, quote_token = await harness.build_quote(network="aws:base")
        payment_token = harness.issue_payment_token(quote_token, sub=harness.agent_pay_id)

        facilitator = AgentPayFacilitatorClient()
        result = facilitator.verify(payment_token, quote_token, _requirements_for(requirements))
        assert result.is_valid is True

    @respx.mock
    async def test_flow_on_eip155(self, harness: Any) -> None:
        harness.mock_jwks(respx.mock)
        requirements, quote_token = await harness.build_quote(network="eip155:8453")
        payment_token = harness.issue_payment_token(quote_token, sub=harness.agent_pay_id)

        facilitator = AgentPayFacilitatorClient()
        result = facilitator.verify(payment_token, quote_token, _requirements_for(requirements))
        assert result.is_valid is True
        settle = facilitator.settle(payment_id="awsmp-evm", network="eip155:8453")
        assert settle.network == "eip155:8453"


class TestDpopBoundFlow:
    """A DPoP-bound payment verifies with a matching proof and is rejected without one."""

    @respx.mock
    async def test_dpop_bound_flow_with_matching_proof(self, harness: Any) -> None:
        from fiat_extension_x402 import (
            create_dpop_proof,
            extract_dpop_thumbprint,
            generate_dpop_keypair,
        )

        harness.mock_jwks(respx.mock)
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(keypair, {"htm": "GET", "htu": "https://api.seller.com/r"})
        jkt = extract_dpop_thumbprint(proof)

        requirements, quote_token = await harness.build_quote()
        payment_token = harness.issue_payment_token(
            quote_token, sub=harness.agent_pay_id, cnf_jkt=jkt
        )

        facilitator = AgentPayFacilitatorClient()
        result = facilitator.verify(
            payment_token,
            quote_token,
            _requirements_for(requirements),
            verify_options={
                "dpop_proof": proof,
                "method": "GET",
                "url": "https://api.seller.com/r",
            },
        )
        assert result.is_valid is True

    @respx.mock
    async def test_dpop_bound_without_proof_rejected(self, harness: Any) -> None:
        from fiat_extension_x402 import (
            create_dpop_proof,
            extract_dpop_thumbprint,
            generate_dpop_keypair,
        )

        harness.mock_jwks(respx.mock)
        keypair = generate_dpop_keypair("ES256")
        jkt = extract_dpop_thumbprint(
            create_dpop_proof(keypair, {"htm": "GET", "htu": "https://api.seller.com/r"})
        )

        requirements, quote_token = await harness.build_quote()
        payment_token = harness.issue_payment_token(
            quote_token, sub=harness.agent_pay_id, cnf_jkt=jkt
        )

        facilitator = AgentPayFacilitatorClient()
        result = facilitator.verify(payment_token, quote_token, _requirements_for(requirements))
        assert result.is_valid is False
        assert result.invalid_reason == "dpop_required"


class TestBuilderDrivenFlow:
    """The resource-server builder produces a server that drives the same flow."""

    @respx.mock
    async def test_build_resource_server_then_enhance(self, harness: Any) -> None:
        from fiat_extension_x402.builders import (
            AgentPayResourceServerOptions,
            create_agent_pay_resource_server,
        )

        harness.mock_jwks(respx.mock)
        server = create_agent_pay_resource_server(
            AgentPayResourceServerOptions(
                agent_pay_base_url="https://pay.example.com",
                agent_pay_id=harness.agent_pay_id,
                signer=harness.seller_signer,
                service_url="https://seller.integration.example.com",
            )
        )
        server.register_network("aws:base")

        requirements = await server.build_payment_requirements(
            network="aws:base", price="0.15", pay_to="service-pay"
        )
        quote_token = requirements["extra"]["quoteToken"]
        payment_token = harness.issue_payment_token(quote_token, sub=harness.agent_pay_id)

        facilitator = AgentPayFacilitatorClient()
        result = facilitator.verify(payment_token, quote_token, _requirements_for(requirements))
        assert result.is_valid is True


class TestFrameworkDrivenBuyerFlow:
    """The buyer leg driven through x402 core rather than a hand-minted token.

    The seller's enhanced requirements become a ``PaymentRequired``; x402 core
    selects the agent-pay offer, dispatches to the registered Agent Pay scheme,
    and the scheme calls the (mocked) CreateAgentPayment endpoint. The resulting
    payment token is then verified by the seller's facilitator — so the whole
    round-trip runs through real SDK code end to end.
    """

    @respx.mock
    async def test_create_payment_payload_round_trip(self, harness: Any) -> None:
        harness.mock_jwks(respx.mock)
        buyer = harness.build_buyer(respx.mock)

        requirements, quote_token = await harness.build_quote(amount="0.15")
        payload = buyer.create_payment_payload(_payment_required(requirements))

        # x402 core wrapped the scheme's inner payload into a full PaymentPayload.
        assert payload.x402_version == 2
        assert payload.accepted.scheme == "agent-pay"
        assert payload.accepted.network == "aws:base"
        assert payload.payload["paymentId"].startswith("awsmp-")
        assert payload.payload["transactionId"] == payload.payload["paymentId"]

        # The buyer forwarded only the signed quote (plus its idempotency key).
        assert harness.create_payment_requests[0]["quoteToken"] == quote_token
        assert "amount" not in harness.create_payment_requests[0]

        # The seller accepts the token the buyer obtained.
        facilitator = AgentPayFacilitatorClient()
        result = facilitator.verify(
            payload.payload["paymentToken"], quote_token, _requirements_for(requirements)
        )
        assert result.is_valid is True
        assert result.payer == harness.agent_pay_id

    @respx.mock
    async def test_encoded_payment_header_round_trip(self, harness: Any) -> None:
        """The payload encodes to the v2 PAYMENT-SIGNATURE header via x402 core."""
        from x402.http import x402HTTPClientSync

        harness.mock_jwks(respx.mock)
        buyer = harness.build_buyer(respx.mock)

        requirements, quote_token = await harness.build_quote()
        payload = buyer.create_payment_payload(_payment_required(requirements))

        headers = x402HTTPClientSync(buyer.client).encode_payment_signature_header(payload)
        assert "PAYMENT-SIGNATURE" in headers

        decoded = json.loads(base64.b64decode(headers["PAYMENT-SIGNATURE"]))
        assert decoded["x402Version"] == 2
        assert decoded["payload"]["paymentToken"] == payload.payload["paymentToken"]
        assert decoded["accepted"]["extra"]["quoteToken"] == quote_token

    @respx.mock
    async def test_framework_flow_on_eip155(self, harness: Any) -> None:
        harness.mock_jwks(respx.mock)
        buyer = harness.build_buyer(respx.mock)

        requirements, quote_token = await harness.build_quote(network="eip155:8453")
        payload = buyer.create_payment_payload(_payment_required(requirements))
        assert payload.accepted.network == "eip155:8453"

        facilitator = AgentPayFacilitatorClient()
        result = facilitator.verify(
            payload.payload["paymentToken"], quote_token, _requirements_for(requirements)
        )
        assert result.is_valid is True

    @respx.mock
    async def test_dpop_bound_framework_flow(self, harness: Any) -> None:
        """A DPoP key on the scheme binds the token core-side, end to end."""
        from fiat_extension_x402 import (
            create_dpop_proof,
            generate_dpop_keypair,
            to_dpop_jwk,
        )

        harness.mock_jwks(respx.mock)
        keypair = generate_dpop_keypair("ES256")
        buyer = harness.build_buyer(respx.mock, dpop_jwk=to_dpop_jwk(keypair))

        requirements, quote_token = await harness.build_quote()
        payload = buyer.create_payment_payload(_payment_required(requirements))
        assert harness.create_payment_requests[0]["dpopJwk"]["kty"] == "EC"

        proof = create_dpop_proof(keypair, {"htm": "GET", "htu": "https://api.seller.com/r"})
        facilitator = AgentPayFacilitatorClient()
        result = facilitator.verify(
            payload.payload["paymentToken"],
            quote_token,
            _requirements_for(requirements),
            verify_options={
                "dpop_proof": proof,
                "method": "GET",
                "url": "https://api.seller.com/r",
            },
        )
        assert result.is_valid is True

    @respx.mock
    async def test_missing_quote_token_rejected_before_any_call(self, harness: Any) -> None:
        harness.mock_jwks(respx.mock)
        buyer = harness.build_buyer(respx.mock)

        requirements, _ = await harness.build_quote()
        stripped = {**requirements, "extra": {}}

        with pytest.raises(ValidationError, match="Missing quoteToken"):
            buyer.create_payment_payload(_payment_required(stripped))
        assert harness.create_payment_requests == []


class TestAllThreeRolesThroughX402Core:
    """Seller, buyer, and verifier all driven through x402 core.

    Every leg goes through the framework: ``x402ResourceServerSync`` builds the
    402, ``x402ClientSync`` pays it, and ``x402FacilitatorSync`` verifies and
    settles — with this SDK's three scheme classes registered on each.
    """

    @respx.mock
    async def test_framework_round_trip(self, harness: Any) -> None:
        from x402 import x402ClientSync, x402FacilitatorSync, x402ResourceServerSync
        from x402.schemas import ResourceConfig

        from fiat_extension_x402 import (
            AgentPayClientScheme,
            AgentPayFacilitatorScheme,
            AgentPayServerScheme,
        )

        harness.mock_jwks(respx.mock)
        harness.mock_create_agent_payment(respx.mock)

        # The seller's own facilitator advertises the supported kinds its
        # resource server needs before it can build requirements.
        facilitator = x402FacilitatorSync()
        facilitator.register(["aws:base"], AgentPayFacilitatorScheme())
        supported = facilitator.get_supported()
        assert [(k.scheme, k.network) for k in supported.kinds] == [("agent-pay", "aws:base")]

        # Seller leg.
        server = x402ResourceServerSync(facilitator)
        server.register("aws:base", AgentPayServerScheme(signer=harness.seller_signer))
        server.initialize()
        requirements = server.build_payment_requirements(
            ResourceConfig(
                scheme="agent-pay", network="aws:base", pay_to="service-pay", price="$0.15"
            )
        )
        offer = requirements[0]
        assert offer.amount == "0.15"
        assert offer.asset == "iso4217:USD"
        assert offer.pay_to == AGENT_PAY_SENTINEL_PAY_TO
        quote_token = offer.extra["quoteToken"]
        payment_required = server.create_payment_required_response(requirements)

        # Buyer leg.
        buyer = x402ClientSync()
        buyer.register(
            "aws:base",
            AgentPayClientScheme(
                agent_pay_id=harness.agent_pay_id,
                agent_pay=harness.agent_pay_config(),
            ),
        )
        payload = buyer.create_payment_payload(payment_required)
        assert isinstance(payload, PaymentPayload)
        assert payload.payload["paymentId"].startswith("awsmp-")
        assert harness.create_payment_requests[0]["quoteToken"] == quote_token

        # Verifier leg — note it verifies against payload.accepted, the offer
        # core selected, with no hand-threading of the quote token.
        verified = facilitator.verify(payload, payload.accepted)
        assert verified.is_valid is True
        assert verified.payer == harness.agent_pay_id

        settled = facilitator.settle(payload, payload.accepted)
        assert settled.success is True
        assert settled.transaction == payload.payload["paymentId"]
        assert settled.network == "aws:base"

    @respx.mock
    async def test_framework_verifier_rejects_a_mismatched_quote(self, harness: Any) -> None:
        """A payment for one quote must not satisfy requirements for another."""
        from x402 import x402FacilitatorSync
        from x402.schemas import PaymentPayload

        from fiat_extension_x402 import AgentPayFacilitatorScheme

        harness.mock_jwks(respx.mock)

        _requirements, quote_token = await harness.build_quote(amount="0.15")
        other_requirements, _ = await harness.build_quote(amount="9.99")
        payment_token = harness.issue_payment_token(quote_token, sub=harness.agent_pay_id)

        facilitator = x402FacilitatorSync()
        facilitator.register(["aws:base"], AgentPayFacilitatorScheme())

        payload = PaymentPayload(
            x402_version=2,
            payload={"paymentToken": payment_token, "paymentId": "awsmp-mismatch"},
            accepted=PaymentRequirements.model_validate(other_requirements),
        )
        result = facilitator.verify(payload, payload.accepted)
        assert result.is_valid is False
        assert result.invalid_reason == "invalid_quote"


class TestNegativeFlow:
    """End-to-end rejection paths."""

    @respx.mock
    async def test_quote_token_mismatch_rejected(self, harness: Any) -> None:
        harness.mock_jwks(respx.mock)
        requirements, quote_token = await harness.build_quote(amount="0.15")
        _, other_quote = await harness.build_quote(amount="9.99")
        # Payment token embeds `quote_token`, but the seller expects `other_quote`.
        payment_token = harness.issue_payment_token(quote_token, sub=harness.agent_pay_id)

        facilitator = AgentPayFacilitatorClient()
        result = facilitator.verify(payment_token, other_quote, _requirements_for(requirements))
        assert result.is_valid is False
        assert result.invalid_reason == "invalid_quote"

    @respx.mock
    async def test_expired_payment_token_rejected(self, harness: Any) -> None:
        harness.mock_jwks(respx.mock)
        requirements, quote_token = await harness.build_quote()
        payment_token = harness.issue_payment_token(
            quote_token, sub=harness.agent_pay_id, exp_offset=-10
        )

        facilitator = AgentPayFacilitatorClient()
        result = facilitator.verify(payment_token, quote_token, _requirements_for(requirements))
        assert result.is_valid is False
        assert result.invalid_reason == "payment_expired"

    @respx.mock
    async def test_amount_mismatch_rejected(self, harness: Any) -> None:
        harness.mock_jwks(respx.mock)
        _requirements, quote_token = await harness.build_quote(amount="0.15")
        payment_token = harness.issue_payment_token(quote_token, sub=harness.agent_pay_id)

        facilitator = AgentPayFacilitatorClient()
        bad_requirements = {"amount": "9.99", "asset": "iso4217:USD", "network": "aws:base"}
        result = facilitator.verify(payment_token, quote_token, bad_requirements)
        assert result.is_valid is False
        assert result.invalid_reason == "invalid_payment"
