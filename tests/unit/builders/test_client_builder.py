# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for fiat_extension_x402.builders.client_builder module."""

from __future__ import annotations

from typing import Any

import pytest
from x402 import x402ClientSync
from x402.schemas import (
    PaymentPayload,
    PaymentRequired,
    PaymentRequiredV1,
    PaymentRequirements,
)
from x402.schemas.errors import NoMatchingRequirementsError

from fiat_extension_x402.builders.client_builder import (
    AgentPayClientBuilder,
    AgentPayClientConfig,
    AgentPayClientOptions,
    build_agent_pay_client,
    create_agent_pay_client,
)
from fiat_extension_x402.client import AgentPayClient
from fiat_extension_x402.client_scheme import AgentPayClientScheme
from fiat_extension_x402.constants import AGENT_PAY_SCHEME, AGENT_PAY_SENTINEL_PAY_TO
from fiat_extension_x402.exceptions import ValidationError

_PAYMENT_ID = "awsmp-00000000-0000-0000-0000-000000000001"


def _payment_required(network: str = "aws:base") -> PaymentRequired:
    """A 402 body carrying a single agent-pay offer."""
    return PaymentRequired(
        x402_version=2,
        accepts=[
            PaymentRequirements.model_validate(
                {
                    "scheme": AGENT_PAY_SCHEME,
                    "network": network,
                    "asset": "iso4217:USD",
                    "amount": "0.15",
                    "payTo": AGENT_PAY_SENTINEL_PAY_TO,
                    "maxTimeoutSeconds": 300,
                    "extra": {"quoteToken": "eyJ.quote.token"},
                }
            )
        ],
    )


def _mock_create_payment(builder: AgentPayClientBuilder) -> Any:
    """Stub the Agent Pay CreateAgentPayment endpoint for a builder's client."""
    import httpx
    import respx

    router = respx.mock
    router.post(f"{builder.agent_pay_client._base_url}/CreateAgentPayment").mock(
        return_value=httpx.Response(
            200,
            json={
                "paymentId": _PAYMENT_ID,
                "paymentToken": "tok-abc",
                "createdAt": "2025-01-01T00:00:00Z",
            },
        )
    )
    return router


class TestCreateAgentPayClient:
    def test_creates_builder(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        assert isinstance(builder, AgentPayClientBuilder)
        assert isinstance(builder.agent_pay_client, AgentPayClient)

    def test_custom_base_url(self) -> None:
        builder = create_agent_pay_client(
            AgentPayClientOptions(
                agent_pay_id="test-id",
                agent_pay_base_url="https://custom.example.com",
            )
        )
        assert builder.agent_pay_client is not None

    def test_invalid_base_url(self) -> None:
        with pytest.raises(ValidationError, match="Invalid agentPayBaseUrl"):
            create_agent_pay_client(
                AgentPayClientOptions(
                    agent_pay_id="test-id",
                    agent_pay_base_url="not-a-url",
                )
            )

    def test_empty_base_url_defaults(self) -> None:
        """An empty base URL falls back to the production default."""
        builder = create_agent_pay_client(
            AgentPayClientOptions(agent_pay_id="test-id", agent_pay_base_url="")
        )
        assert isinstance(builder, AgentPayClientBuilder)
        assert isinstance(builder.agent_pay_client, AgentPayClient)


class TestAgentPayClientBuilder:
    def test_register_network_returns_self(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        result = builder.register_network("aws:base")
        assert result is builder

    def test_register_network_chaining(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        result = builder.register_network("aws:base").register_network("eip155:8453")
        assert result is builder
        assert builder.registered_networks == {"aws:base", "eip155:8453"}

    def test_register_network_idempotent(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        builder.register_network("aws:base")
        builder.register_network("aws:base")  # Should not error.
        assert builder.registered_networks == {"aws:base"}

    def test_client_property(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        assert isinstance(builder.agent_pay_client, AgentPayClient)

    def test_exposes_x402_client_and_scheme(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        assert isinstance(builder.client, x402ClientSync)
        assert isinstance(builder.scheme, AgentPayClientScheme)

    def test_register_network_registers_scheme_with_x402_core(self) -> None:
        """The scheme must actually reach x402 core, not just a local set."""
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        builder.register_network("aws:base")

        with _mock_create_payment(builder):
            payload = builder.client.create_payment_payload(_payment_required())

        assert payload.payload["paymentId"] == _PAYMENT_ID

    def test_unregistered_network_is_not_served(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        builder.register_network("aws:base")

        with pytest.raises(NoMatchingRequirementsError):
            builder.client.create_payment_payload(_payment_required(network="eip155:8453"))

    def test_accepts_existing_x402_client(self) -> None:
        existing = x402ClientSync()
        builder = create_agent_pay_client(
            AgentPayClientOptions(agent_pay_id="test-id", existing_client=existing)
        )
        assert builder.client is existing


class TestAgentPayClientBuilderCreatePaymentPayload:
    def test_returns_full_x402_payload(self) -> None:
        """The framework path wraps the scheme payload into a full PaymentPayload."""
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        builder.register_network("aws:base")

        with _mock_create_payment(builder):
            payload = builder.create_payment_payload(_payment_required())

        assert isinstance(payload, PaymentPayload)
        assert payload.x402_version == 2
        assert payload.accepted.scheme == AGENT_PAY_SCHEME
        assert payload.accepted.network == "aws:base"
        assert payload.payload == {
            "paymentToken": "tok-abc",
            "paymentId": _PAYMENT_ID,
            "transactionId": _PAYMENT_ID,
        }

    def test_serves_x402_v1_payment_required(self) -> None:
        """This SDK's own middleware emits x402Version 1, so v1 must be served."""
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        builder.register_network("aws:base")

        v1_required = PaymentRequiredV1.model_validate(
            {
                "x402Version": 1,
                "accepts": [
                    {
                        "scheme": AGENT_PAY_SCHEME,
                        "network": "aws:base",
                        "maxAmountRequired": "0.15",
                        "resource": "https://api.seller.example.com/premium",
                        "payTo": AGENT_PAY_SENTINEL_PAY_TO,
                        "maxTimeoutSeconds": 300,
                        "asset": "iso4217:USD",
                        "extra": {"quoteToken": "eyJ.quote.token"},
                    }
                ],
            }
        )

        with _mock_create_payment(builder):
            payload = builder.create_payment_payload(v1_required)

        assert payload.x402_version == 1
        assert payload.payload["paymentId"] == _PAYMENT_ID

    def test_wildcard_network_registration(self) -> None:
        """x402 core resolves wildcard families, so aws:* serves aws:base."""
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        builder.register_network("aws:*")

        with _mock_create_payment(builder):
            payload = builder.create_payment_payload(_payment_required(network="aws:base"))

        assert payload.payload["paymentId"] == _PAYMENT_ID


class TestAgentPayClientBuilderCreatePayment:
    def test_create_payment_delegates_to_client(self) -> None:
        import httpx
        import respx

        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))

        payment_id = "awsmp-00000000-0000-0000-0000-000000000001"
        with respx.mock:
            respx.post(f"{builder.agent_pay_client._base_url}/CreateAgentPayment").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "paymentId": payment_id,
                        "paymentToken": "tok-abc",
                        "createdAt": "2025-01-01T00:00:00Z",
                    },
                )
            )
            result = builder.create_payment(quote_token="mock.qt")

        assert result.payment_id == payment_id
        assert result.payment_token == "tok-abc"


class TestBuildAgentPayClient:
    def test_returns_x402_client(self) -> None:
        """The convenience builder returns the configured x402 client."""
        client = build_agent_pay_client(
            AgentPayClientConfig(
                networks=["aws:base"],
                agent_pay_id="test-id",
            )
        )
        assert isinstance(client, x402ClientSync)

    def test_registers_requested_networks(self) -> None:
        """The returned client serves the networks it was built for."""
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        builder.register_network("aws:base")

        with _mock_create_payment(builder):
            payload = builder.client.create_payment_payload(_payment_required())

        assert payload.payload["paymentId"] == _PAYMENT_ID

    def test_empty_networks_raises(self) -> None:
        with pytest.raises(ValidationError, match="networks must be a non-empty array"):
            build_agent_pay_client(
                AgentPayClientConfig(
                    networks=[],
                    agent_pay_id="test-id",
                )
            )

    def test_multiple_networks(self) -> None:
        client = build_agent_pay_client(
            AgentPayClientConfig(
                networks=["aws:base", "eip155:8453"],
                agent_pay_id="test-id",
            )
        )
        assert isinstance(client, x402ClientSync)
