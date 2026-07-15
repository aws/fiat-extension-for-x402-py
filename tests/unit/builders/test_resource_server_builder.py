# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for fiat_extension_x402.builders.resource_server_builder module."""

from __future__ import annotations

from typing import Any

import pytest

from fiat_extension_x402.builders.resource_server_builder import (
    AgentPayResourceServer,
    AgentPayResourceServerConfig,
    AgentPayResourceServerOptions,
    build_agent_pay_resource_server,
    create_agent_pay_resource_server,
)
from fiat_extension_x402.exceptions import ValidationError


class MockSigner:
    """Mock signer for testing."""

    async def sign_quote(self, payload: dict[str, Any]) -> str:
        return "mock.jwt.token"

    def get_public_key(self) -> object:
        return {"kty": "EC", "crv": "P-384"}

    def get_service_url(self) -> str:
        return "https://api.example.com"


class TestCreateAgentPayResourceServer:
    def test_creates_server(self) -> None:
        server = create_agent_pay_resource_server(
            AgentPayResourceServerOptions(
                agent_pay_base_url="https://pay.aws.amazon.com",
                agent_pay_id="test-id",
                signer=MockSigner(),
                service_url="https://api.example.com",
            )
        )
        assert isinstance(server, AgentPayResourceServer)

    def test_empty_base_url_defaults(self) -> None:
        """An empty base URL falls back to the production default."""
        server = create_agent_pay_resource_server(
            AgentPayResourceServerOptions(
                agent_pay_base_url="",
                agent_pay_id="test-id",
                signer=MockSigner(),
                service_url="https://api.example.com",
            )
        )
        assert isinstance(server, AgentPayResourceServer)

    def test_invalid_base_url(self) -> None:
        with pytest.raises(ValidationError, match="Invalid agentPayBaseUrl"):
            create_agent_pay_resource_server(
                AgentPayResourceServerOptions(
                    agent_pay_base_url="not-a-url",
                    agent_pay_id="test-id",
                    signer=MockSigner(),
                    service_url="https://api.example.com",
                )
            )

    def test_missing_service_url(self) -> None:
        with pytest.raises(ValidationError, match="serviceUrl is required"):
            create_agent_pay_resource_server(
                AgentPayResourceServerOptions(
                    agent_pay_base_url="https://pay.aws.amazon.com",
                    agent_pay_id="test-id",
                    signer=MockSigner(),
                    service_url="",
                )
            )


class TestAgentPayResourceServerProperties:
    def test_signer_property(self) -> None:
        signer = MockSigner()
        server = create_agent_pay_resource_server(
            AgentPayResourceServerOptions(
                agent_pay_base_url="https://pay.aws.amazon.com",
                agent_pay_id="test-id",
                signer=signer,
                service_url="https://api.example.com",
            )
        )
        assert server.signer is signer

    def test_missing_signer_raises(self) -> None:
        with pytest.raises(ValidationError, match="signer is required"):
            create_agent_pay_resource_server(
                AgentPayResourceServerOptions(
                    agent_pay_base_url="https://pay.aws.amazon.com",
                    agent_pay_id="test-id",
                    signer=None,  # type: ignore[arg-type]
                    service_url="https://api.example.com",
                )
            )


class TestAgentPayResourceServer:
    def test_register_network_returns_self(self) -> None:
        server = create_agent_pay_resource_server(
            AgentPayResourceServerOptions(
                agent_pay_base_url="https://pay.aws.amazon.com",
                agent_pay_id="test-id",
                signer=MockSigner(),
                service_url="https://api.example.com",
            )
        )
        result = server.register_network("aws:base")
        assert result is server

    def test_register_network_chaining(self) -> None:
        server = create_agent_pay_resource_server(
            AgentPayResourceServerOptions(
                agent_pay_base_url="https://pay.aws.amazon.com",
                agent_pay_id="test-id",
                signer=MockSigner(),
                service_url="https://api.example.com",
            )
        )
        result = server.register_network("aws:base").register_network("eip155:8453")
        assert result is server

    def test_register_network_idempotent(self) -> None:
        server = create_agent_pay_resource_server(
            AgentPayResourceServerOptions(
                agent_pay_base_url="https://pay.aws.amazon.com",
                agent_pay_id="test-id",
                signer=MockSigner(),
                service_url="https://api.example.com",
            )
        )
        server.register_network("aws:base")
        server.register_network("aws:base")  # No error.
        assert server.registered_networks == {"aws:base"}

    def test_initialize_no_networks_raises(self) -> None:
        server = create_agent_pay_resource_server(
            AgentPayResourceServerOptions(
                agent_pay_base_url="https://pay.aws.amazon.com",
                agent_pay_id="test-id",
                signer=MockSigner(),
                service_url="https://api.example.com",
            )
        )
        with pytest.raises(ValidationError, match="No networks registered"):
            server.initialize()

    def test_initialize_success(self) -> None:
        server = create_agent_pay_resource_server(
            AgentPayResourceServerOptions(
                agent_pay_base_url="https://pay.aws.amazon.com",
                agent_pay_id="test-id",
                signer=MockSigner(),
                service_url="https://api.example.com",
            )
        )
        server.register_network("aws:base")
        result = server.initialize()
        assert result is server

    def test_register_after_initialize_raises(self) -> None:
        server = create_agent_pay_resource_server(
            AgentPayResourceServerOptions(
                agent_pay_base_url="https://pay.aws.amazon.com",
                agent_pay_id="test-id",
                signer=MockSigner(),
                service_url="https://api.example.com",
            )
        )
        server.register_network("aws:base")
        server.initialize()
        with pytest.raises(ValidationError, match="Cannot register networks after initialize"):
            server.register_network("eip155:8453")

    async def test_build_payment_requirements(self) -> None:
        server = create_agent_pay_resource_server(
            AgentPayResourceServerOptions(
                agent_pay_base_url="https://pay.aws.amazon.com",
                agent_pay_id="test-id",
                signer=MockSigner(),
                service_url="https://api.example.com",
            )
        )
        server.register_network("aws:base")
        server.initialize()

        requirements = await server.build_payment_requirements(
            network="aws:base",
            pay_to="seller-id",
            price="0.15",
            asset="iso4217:USD",
            extra={"description": "Premium content"},
        )
        assert requirements["extra"]["quoteToken"] == "mock.jwt.token"
        assert requirements["amount"] == "0.15"


class TestBuildAgentPayResourceServer:
    def test_returns_initialized_server(self) -> None:
        server = build_agent_pay_resource_server(
            AgentPayResourceServerConfig(
                networks=["aws:base"],
                agent_pay_base_url="https://pay.aws.amazon.com",
                agent_pay_id="test-id",
                signer=MockSigner(),
                service_url="https://api.example.com",
            )
        )
        assert isinstance(server, AgentPayResourceServer)
        assert server.registered_networks == {"aws:base"}

    def test_empty_networks_raises(self) -> None:
        with pytest.raises(ValidationError, match="networks must be a non-empty array"):
            build_agent_pay_resource_server(
                AgentPayResourceServerConfig(
                    networks=[],
                    agent_pay_base_url="https://pay.aws.amazon.com",
                    agent_pay_id="test-id",
                    signer=MockSigner(),
                    service_url="https://api.example.com",
                )
            )

    def test_multiple_networks(self) -> None:
        server = build_agent_pay_resource_server(
            AgentPayResourceServerConfig(
                networks=["aws:base", "eip155:8453"],
                agent_pay_base_url="https://pay.aws.amazon.com",
                agent_pay_id="test-id",
                signer=MockSigner(),
                service_url="https://api.example.com",
            )
        )
        assert server.registered_networks == {"aws:base", "eip155:8453"}
