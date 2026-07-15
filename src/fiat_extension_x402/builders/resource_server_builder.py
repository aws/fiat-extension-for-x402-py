# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Agent Pay Resource Server Builder.

Two-phase API: create a server, then register networks.

Usage::

    server = create_agent_pay_resource_server(AgentPayResourceServerOptions(
        agent_pay_base_url="https://pay.aws.amazon.com",
        agent_pay_id="my-agent-pay",
        signer=my_signer,
        service_url="https://api.example.com",
    ))
    server.register_network("aws:base")

Or use the convenience builder::

    from fiat_extension_x402.builders import build_agent_pay_resource_server

    server = build_agent_pay_resource_server(AgentPayResourceServerConfig(
        networks=["aws:base"],
        agent_pay_base_url="https://pay.aws.amazon.com",
        agent_pay_id="my-agent-pay",
        signer=my_signer,
        service_url="https://api.example.com",
    ))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from fiat_extension_x402.constants import DEFAULT_AGENT_PAY_BASE_URL
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.facilitator import AgentPayFacilitatorClient
from fiat_extension_x402.server import enhance_payment_requirements
from fiat_extension_x402.signers.protocol import ServiceAgentPaySigner


@dataclass
class AgentPayResourceServerOptions:
    """Base configuration for creating an Agent Pay resource server.

    :param agent_pay_base_url: Agent Pay base URL for the facilitator.
    :param agent_pay_id: Agent Pay ID for the facilitator.
    :param signer: Service signer for quote tokens.
    :param service_url: Service URL (used as issuer in quote tokens).
    """

    agent_pay_base_url: str
    agent_pay_id: str
    signer: ServiceAgentPaySigner
    service_url: str


@dataclass
class InitializeOptions:
    """Options passed to :meth:`AgentPayResourceServer.initialize`.

    :param disable_default_fallback: Disable default facilitator fallback entirely.
    """

    disable_default_fallback: bool = False


@dataclass
class NetworkOptions:
    """Per-network options (reserved for future use).

    :param facilitator_url: Override facilitator URL for this specific network.
    """

    facilitator_url: Optional[str] = None


@dataclass
class AgentPayResourceServerConfig:
    """Configuration for the convenience :func:`build_agent_pay_resource_server`.

    :param networks: Networks to register.
    :param agent_pay_base_url: Agent Pay base URL for the facilitator.
    :param agent_pay_id: Agent Pay ID for the facilitator.
    :param signer: Service signer for quote tokens.
    :param service_url: Service URL (used as issuer in quote tokens).
    :param disable_default_fallback: Disable default facilitator fallback.
    """

    networks: list[str]
    agent_pay_base_url: str
    agent_pay_id: str
    signer: ServiceAgentPaySigner
    service_url: str
    disable_default_fallback: bool = False


class AgentPayResourceServer:
    """Agent Pay resource server with a fluent ``register_network`` API.

    Call :meth:`initialize` after registering all networks.
    """

    def __init__(
        self,
        *,
        signer: ServiceAgentPaySigner,
        service_url: str,
        facilitator: AgentPayFacilitatorClient,
    ) -> None:
        self._signer = signer
        self._service_url = service_url
        self._facilitator = facilitator
        self._registered_networks: set[str] = set()
        self._initialized = False

    @property
    def signer(self) -> ServiceAgentPaySigner:
        """The service signer for quote tokens."""
        return self._signer

    @property
    def facilitator(self) -> AgentPayFacilitatorClient:
        """The Agent Pay facilitator client."""
        return self._facilitator

    @property
    def registered_networks(self) -> set[str]:
        """The set of registered networks."""
        return set(self._registered_networks)

    def register_network(
        self, network: str, options: Optional[NetworkOptions] = None
    ) -> AgentPayResourceServer:
        """Register a network for Agent Pay to handle.

        Returns ``self`` for chaining. Idempotent — re-registering the same
        network is a no-op.

        :param network: Network identifier (e.g., ``'aws:base'``).
        :param options: Per-network options (reserved for future use).
        :raises ValidationError: if called after :meth:`initialize`.
        """
        if self._initialized:
            raise ValidationError("Cannot register networks after initialize()")
        if network in self._registered_networks:
            return self
        self._registered_networks.add(network)
        return self

    def initialize(self, options: Optional[InitializeOptions] = None) -> AgentPayResourceServer:
        """Initialize the server.

        Must be called after registering all networks.

        :param options: Initialization options.
        :returns: ``self`` for convenience.
        :raises ValidationError: if no networks are registered.
        """
        if not self._registered_networks:
            raise ValidationError(
                "No networks registered. Call register_network() before initialize()."
            )
        self._initialized = True
        return self

    async def build_payment_requirements(
        self,
        *,
        network: str,
        pay_to: str,
        price: Any,
        asset: str = "iso4217:USD",
        extra: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Build payment requirements with a signed quote token.

        :param network: Network identifier.
        :param pay_to: Recipient Agent Pay ID.
        :param price: Price for this resource.
        :param asset: Asset identifier (e.g., ``'iso4217:USD'``).
        :param extra: Additional fields to include in the quote token.
        :returns: Enhanced payment requirements with signed quote token.
        """
        base_requirements: dict[str, Any] = {
            "scheme": "agent-pay",
            "network": network,
            "payTo": pay_to,
            "amount": str(price),
            "asset": asset,
            "extra": extra or {},
        }

        return await enhance_payment_requirements(base_requirements, self._signer)


def _validate_base_config(config: AgentPayResourceServerOptions) -> None:
    """Validate resource server options.

    An empty ``agent_pay_base_url`` falls back to the production default; a
    non-empty but malformed URL still raises.
    """
    resolved_base_url = config.agent_pay_base_url or DEFAULT_AGENT_PAY_BASE_URL
    try:
        import httpx as _httpx

        parsed = _httpx.URL(resolved_base_url)
        if not parsed.scheme or not parsed.host:
            raise ValueError("missing scheme or host")
    except Exception:
        raise ValidationError(f"Invalid agentPayBaseUrl: {config.agent_pay_base_url}")
    if not config.signer:
        raise ValidationError("signer is required")
    if not config.service_url:
        raise ValidationError("serviceUrl is required")


def create_agent_pay_resource_server(
    config: AgentPayResourceServerOptions,
) -> AgentPayResourceServer:
    """Create an Agent Pay resource server.

    Networks are registered separately via
    :meth:`AgentPayResourceServer.register_network`, then
    :meth:`AgentPayResourceServer.initialize` finalizes the setup.

    :param config: Resource server options.
    :returns: A resource server builder with a fluent network registration API.
    :raises ValidationError: if configuration is invalid.
    """
    _validate_base_config(config)

    facilitator = AgentPayFacilitatorClient()

    return AgentPayResourceServer(
        signer=config.signer,
        service_url=config.service_url,
        facilitator=facilitator,
    )


def build_agent_pay_resource_server(
    config: AgentPayResourceServerConfig,
) -> AgentPayResourceServer:
    """Convenience builder that creates, registers networks, and initializes.

    :param config: Full resource server configuration including networks.
    :returns: Initialized :class:`AgentPayResourceServer`.
    :raises ValidationError: if networks is empty or configuration is invalid.
    """
    if not config.networks:
        raise ValidationError("networks must be a non-empty array")

    server = create_agent_pay_resource_server(
        AgentPayResourceServerOptions(
            agent_pay_base_url=config.agent_pay_base_url,
            agent_pay_id=config.agent_pay_id,
            signer=config.signer,
            service_url=config.service_url,
        )
    )

    for network in config.networks:
        server.register_network(network)

    server.initialize(
        InitializeOptions(
            disable_default_fallback=config.disable_default_fallback,
        )
    )

    return server


__all__ = [
    "AgentPayResourceServer",
    "AgentPayResourceServerConfig",
    "AgentPayResourceServerOptions",
    "InitializeOptions",
    "NetworkOptions",
    "build_agent_pay_resource_server",
    "create_agent_pay_resource_server",
]
