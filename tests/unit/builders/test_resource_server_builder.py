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


def _make_server(**overrides: Any) -> AgentPayResourceServer:
    """Build a resource server with sensible defaults for these tests."""
    options: dict[str, Any] = {
        "agent_pay_base_url": "https://pay.aws.amazon.com",
        "agent_pay_id": "test-id",
        "signer": MockSigner(),
        "service_url": "https://api.example.com",
    }
    options.update(overrides)
    return create_agent_pay_resource_server(AgentPayResourceServerOptions(**options))


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


class TestBuildPaymentRequirementsPriceParsing:
    """The builder parses prices instead of stringifying whatever it is handed.

    An unvalidated price used to be signed straight into the quote token, so a
    malformed value failed later at Agent Pay on the buyer's call rather than
    here at the seller.
    """

    @pytest.mark.parametrize(
        ("price", "amount", "asset"),
        [
            ("0.15", "0.15", "iso4217:USD"),
            ("$10.00", "10.0", "iso4217:USD"),
            ("2.00 EUR", "2.0", "iso4217:EUR"),
            (0.15, "0.15", "iso4217:USD"),
            (3, "3.0", "iso4217:USD"),
        ],
    )
    async def test_normalises_valid_prices(self, price: object, amount: str, asset: str) -> None:
        server = _make_server()
        server.register_network("aws:base")
        result = await server.build_payment_requirements(
            network="aws:base", pay_to="seller-1", price=price
        )
        assert result["amount"] == amount
        assert result["asset"] == asset

    @pytest.mark.parametrize("price", ["free please", "abc", ""])
    async def test_rejects_malformed_prices(self, price: str) -> None:
        server = _make_server()
        server.register_network("aws:base")
        with pytest.raises(ValidationError, match="Invalid money format"):
            await server.build_payment_requirements(
                network="aws:base", pay_to="seller-1", price=price
            )

    async def test_rejects_a_missing_price(self) -> None:
        server = _make_server()
        server.register_network("aws:base")
        with pytest.raises(ValidationError, match="price is required"):
            await server.build_payment_requirements(
                network="aws:base", pay_to="seller-1", price=None
            )

    async def test_explicit_asset_is_kept_when_the_price_names_no_currency(self) -> None:
        server = _make_server()
        server.register_network("aws:base")
        result = await server.build_payment_requirements(
            network="aws:base", pay_to="seller-1", price="0.15", asset="iso4217:GBP"
        )
        assert result["asset"] == "iso4217:GBP"


class TestBuilderThreadsConfiguration:
    def test_configured_base_url_reaches_the_facilitator(self) -> None:
        """A beta endpoint used to be validated and then discarded."""
        server = _make_server(agent_pay_base_url="https://beta.agentpay.example.com")
        assert server.facilitator._agent_pay_base_url == "https://beta.agentpay.example.com"

    def test_seller_key_resolver_reaches_the_facilitator(self) -> None:
        from fiat_extension_x402.facilitator.client import JwksSellerKeyResolver

        resolver = JwksSellerKeyResolver(jwks_url="https://keys.example.com")
        server = _make_server(seller_key_resolver=resolver)
        assert server.facilitator._seller_key_resolver is resolver
