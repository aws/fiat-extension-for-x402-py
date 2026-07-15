# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Agent Pay Client Builder.

Two-phase API: create a client, then register networks.

Usage::

    client = create_agent_pay_client(AgentPayClientOptions(
        agent_pay_id="my-agent-pay",
    ))
    client.register_network("aws:base")

Or use the convenience builder::

    from fiat_extension_x402.builders import build_agent_pay_client

    client_obj = build_agent_pay_client(AgentPayClientConfig(
        networks=["aws:base"],
        agent_pay_base_url="https://pay.aws.amazon.com",
        agent_pay_id="my-agent-pay",
    ))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fiat_extension_x402.client import AgentPayClient
from fiat_extension_x402.constants import DEFAULT_AGENT_PAY_BASE_URL
from fiat_extension_x402.exceptions import ValidationError


@dataclass
class AgentPayClientOptions:
    """Base configuration for creating an Agent Pay client.

    Does not include networks — those are added via
    :meth:`AgentPayClientBuilder.register_network`.

    :param agent_pay_id: Agent Pay ID.
    :param agent_pay_base_url: Agent Pay base URL. Defaults to the production endpoint.
    """

    agent_pay_id: str
    agent_pay_base_url: str = DEFAULT_AGENT_PAY_BASE_URL


@dataclass
class AgentPayClientConfig:
    """Configuration for the convenience :func:`build_agent_pay_client`.

    :param networks: Networks to register.
    :param agent_pay_id: Agent Pay ID.
    :param agent_pay_base_url: Agent Pay base URL.
    """

    networks: list[str]
    agent_pay_id: str
    agent_pay_base_url: str = DEFAULT_AGENT_PAY_BASE_URL


class AgentPayClientBuilder:
    """Agent Pay client with a fluent ``register_network`` API.

    :param client: The underlying :class:`~fiat_extension_x402.client.AgentPayClient`.
    """

    def __init__(self, client: AgentPayClient) -> None:
        self._client = client
        self._registered_networks: set[str] = set()

    @property
    def client(self) -> AgentPayClient:
        """The underlying Agent Pay client."""
        return self._client

    def register_network(self, network: str) -> AgentPayClientBuilder:
        """Register a network for Agent Pay to handle.

        Returns ``self`` for chaining. Idempotent — re-registering the same
        network is a no-op.

        :param network: Network identifier (e.g., ``'aws:base'``).
        """
        if network in self._registered_networks:
            return self
        self._registered_networks.add(network)
        return self

    def create_payment(self, **kwargs: Any) -> Any:
        """Shortcut: delegates to ``client.create_payment``."""
        from fiat_extension_x402.schemas import CreateAgentPaymentRequest

        request = CreateAgentPaymentRequest(**kwargs)
        return self._client.create_payment(request)


def _resolve_base_url(base_url: str) -> str:
    """Resolve an Agent Pay base URL, defaulting an empty value to production.

    An empty/falsy base URL falls back to :data:`DEFAULT_AGENT_PAY_BASE_URL`; a
    non-empty but malformed URL raises ``ValidationError``.
    """
    resolved = base_url or DEFAULT_AGENT_PAY_BASE_URL
    try:
        import httpx as _httpx

        parsed = _httpx.URL(resolved)
        if not parsed.scheme or not parsed.host:
            raise ValueError("missing scheme or host")
    except Exception:
        raise ValidationError(f"Invalid agentPayBaseUrl: {base_url}")
    return resolved


def create_agent_pay_client(config: AgentPayClientOptions) -> AgentPayClientBuilder:
    """Create an Agent Pay client.

    Networks are registered separately via
    :meth:`AgentPayClientBuilder.register_network`.

    :param config: Client options.
    :returns: A builder with a fluent network registration API.
    :raises ValidationError: if the configuration is invalid.
    """
    base_url = _resolve_base_url(config.agent_pay_base_url)

    client = AgentPayClient(base_url=base_url)
    return AgentPayClientBuilder(client)


def build_agent_pay_client(config: AgentPayClientConfig) -> AgentPayClient:
    """Convenience builder that creates and registers networks in one call.

    :param config: Full client configuration including networks.
    :returns: Configured :class:`~fiat_extension_x402.client.AgentPayClient`.
    :raises ValidationError: if networks is empty or configuration is invalid.
    """
    if not config.networks:
        raise ValidationError("networks must be a non-empty array")

    builder = create_agent_pay_client(
        AgentPayClientOptions(
            agent_pay_id=config.agent_pay_id,
            agent_pay_base_url=config.agent_pay_base_url,
        )
    )

    for network in config.networks:
        builder.register_network(network)

    return builder.client


__all__ = [
    "AgentPayClientBuilder",
    "AgentPayClientConfig",
    "AgentPayClientOptions",
    "build_agent_pay_client",
    "create_agent_pay_client",
]
