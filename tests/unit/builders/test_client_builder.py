# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for fiat_extension_x402.builders.client_builder module."""

from __future__ import annotations

import pytest

from fiat_extension_x402.builders.client_builder import (
    AgentPayClientBuilder,
    AgentPayClientConfig,
    AgentPayClientOptions,
    build_agent_pay_client,
    create_agent_pay_client,
)
from fiat_extension_x402.client import AgentPayClient
from fiat_extension_x402.exceptions import ValidationError


class TestCreateAgentPayClient:
    def test_creates_builder(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        assert isinstance(builder, AgentPayClientBuilder)
        assert isinstance(builder.client, AgentPayClient)

    def test_custom_base_url(self) -> None:
        builder = create_agent_pay_client(
            AgentPayClientOptions(
                agent_pay_id="test-id",
                agent_pay_base_url="https://custom.example.com",
            )
        )
        assert builder.client is not None

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
        assert isinstance(builder.client, AgentPayClient)


class TestAgentPayClientBuilder:
    def test_register_network_returns_self(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        result = builder.register_network("aws:base")
        assert result is builder

    def test_register_network_chaining(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        result = builder.register_network("aws:base").register_network("eip155:8453")
        assert result is builder

    def test_register_network_idempotent(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        builder.register_network("aws:base")
        builder.register_network("aws:base")  # Should not error.

    def test_client_property(self) -> None:
        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))
        assert isinstance(builder.client, AgentPayClient)


class TestAgentPayClientBuilderCreatePayment:
    def test_create_payment_delegates_to_client(self) -> None:
        import httpx
        import respx

        builder = create_agent_pay_client(AgentPayClientOptions(agent_pay_id="test-id"))

        payment_id = "awsmp-00000000-0000-0000-0000-000000000001"
        with respx.mock:
            respx.post(f"{builder.client._base_url}/CreateAgentPayment").mock(
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
    def test_returns_client(self) -> None:
        client = build_agent_pay_client(
            AgentPayClientConfig(
                networks=["aws:base"],
                agent_pay_id="test-id",
            )
        )
        assert isinstance(client, AgentPayClient)

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
        assert isinstance(client, AgentPayClient)
