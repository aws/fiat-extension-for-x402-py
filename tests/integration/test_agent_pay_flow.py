# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""In-process Agent Pay integration tests.

Exercise the full buyer -> Agent Pay -> seller round-trip by wiring the SDK's
real components together with in-memory JWKS mocks (no network, no credentials).
This is the hermetic counterpart to the live ``tests/e2e`` suite and the
in-process analog of the reference SDK's framework-driven integration tests.

Flow per test:
1. Seller builds enhanced requirements + signed quote (``enhance_payment_requirements``).
2. Mock Agent Pay issues a payment token embedding the quote.
3. Seller verifies the payment token (``AgentPayFacilitatorClient.verify``) against
   the mocked Agent Pay + seller JWKS endpoints.
4. Seller settles (no-op auto-capture).
"""

from __future__ import annotations

from typing import Any

import respx

from fiat_extension_x402 import (
    AgentPayFacilitatorClient,
    InProcessFacilitatorClient,
)
from fiat_extension_x402.constants import AGENT_PAY_SENTINEL_PAY_TO


def _requirements_for(quote_requirements: dict[str, Any]) -> dict[str, Any]:
    """Map enhanced requirements to the facilitator's verify requirements."""
    return {
        "amount": quote_requirements["amount"],
        "asset": quote_requirements["asset"],
        "network": quote_requirements["network"],
    }


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
        assert result.invalid_reason == "invalid_payment"

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
        assert result.invalid_reason == "expired"

    @respx.mock
    async def test_amount_mismatch_rejected(self, harness: Any) -> None:
        harness.mock_jwks(respx.mock)
        requirements, quote_token = await harness.build_quote(amount="0.15")
        payment_token = harness.issue_payment_token(quote_token, sub=harness.agent_pay_id)

        facilitator = AgentPayFacilitatorClient()
        bad_requirements = {"amount": "9.99", "asset": "iso4217:USD", "network": "aws:base"}
        result = facilitator.verify(payment_token, quote_token, bad_requirements)
        assert result.is_valid is False
        assert result.invalid_reason == "invalid_payment"
