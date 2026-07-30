# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Agent Pay Client Builder.

Two-phase API: create a client, then register networks.

Usage::

    client = create_agent_pay_client(AgentPayClientOptions(
        agent_pay_id="my-agent-pay",
        credentials=my_aws_credentials,
    ))
    client.register_network("aws:base")

    # Framework path — x402 core selects the scheme by network + scheme name.
    payload = client.create_payment_payload(payment_required)

Or use the convenience builder::

    from fiat_extension_x402.builders import build_agent_pay_client

    client_obj = build_agent_pay_client(AgentPayClientConfig(
        networks=["aws:base"],
        agent_pay_base_url="https://pay.aws.amazon.com",
        agent_pay_id="my-agent-pay",
    ))

Registering a network wires the Agent Pay scheme into an
:class:`x402.x402ClientSync`, so ``create_payment_payload`` dispatches through
x402 core exactly as any other payment mechanism would. Wildcard families are
supported by core, so ``register_network("aws:*")`` handles every ``aws:``
network.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Optional

from botocore.credentials import Credentials  # type: ignore[import-untyped]
from x402 import x402ClientSync
from x402.schemas import PaymentPayload, PaymentPayloadV1, PaymentRequired, PaymentRequiredV1

from fiat_extension_x402.auth import Authenticator
from fiat_extension_x402.client import AgentPayClient
from fiat_extension_x402.client_scheme import AgentPayClientScheme, AgentPayConfig
from fiat_extension_x402.constants import DEFAULT_AGENT_PAY_BASE_URL
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.schemas import DpopJwk


@dataclass
class AgentPayClientOptions:
    """Base configuration for creating an Agent Pay client.

    Does not include networks — those are added via
    :meth:`AgentPayClientBuilder.register_network`.

    :param agent_pay_id: Agent Pay ID.
    :param agent_pay_base_url: Agent Pay base URL. Defaults to the production endpoint.
    :param authenticator: Authenticator used to sign Agent Pay requests.
    :param credentials: AWS credentials for SigV4 signing (mutually exclusive
        with ``authenticator``).
    :param dpop_jwk: Optional DPoP public key to bind payment tokens to.
    :param client_token_generator: Optional idempotency-key factory.
    :param existing_client: Optional existing ``x402ClientSync`` to register the
        Agent Pay scheme onto, instead of creating a new one.
    """

    agent_pay_id: str
    agent_pay_base_url: str = DEFAULT_AGENT_PAY_BASE_URL
    authenticator: Optional[Authenticator] = None
    credentials: Optional[Credentials] = None
    dpop_jwk: Optional[DpopJwk] = None
    client_token_generator: Optional[Callable[[], str]] = None
    existing_client: Optional[x402ClientSync] = None


@dataclass
class AgentPayClientConfig:
    """Configuration for the convenience :func:`build_agent_pay_client`.

    :param networks: Networks to register.
    :param agent_pay_id: Agent Pay ID.
    :param agent_pay_base_url: Agent Pay base URL.
    :param authenticator: Authenticator used to sign Agent Pay requests.
    :param credentials: AWS credentials for SigV4 signing.
    :param dpop_jwk: Optional DPoP public key to bind payment tokens to.
    :param client_token_generator: Optional idempotency-key factory.
    :param existing_client: Optional existing ``x402ClientSync`` to register onto.
    """

    networks: list[str] = field(default_factory=list)
    agent_pay_id: str = ""
    agent_pay_base_url: str = DEFAULT_AGENT_PAY_BASE_URL
    authenticator: Optional[Authenticator] = None
    credentials: Optional[Credentials] = None
    dpop_jwk: Optional[DpopJwk] = None
    client_token_generator: Optional[Callable[[], str]] = None
    existing_client: Optional[x402ClientSync] = None


class AgentPayClientBuilder:
    """Agent Pay client with a fluent ``register_network`` API.

    Holds three collaborators: the Agent Pay transport
    (:class:`~fiat_extension_x402.client.AgentPayClient`), the buyer scheme
    (:class:`~fiat_extension_x402.client_scheme.AgentPayClientScheme`), and the
    x402 core client the scheme is registered onto.

    :param client: The underlying Agent Pay transport client.
    :param scheme: The Agent Pay buyer scheme.
    :param x402_client: The x402 core client schemes are registered onto.
    """

    def __init__(
        self,
        client: AgentPayClient,
        scheme: AgentPayClientScheme,
        x402_client: x402ClientSync,
    ) -> None:
        self._client = client
        self._scheme = scheme
        self._x402_client = x402_client
        self._registered_networks: set[str] = set()

    @property
    def client(self) -> x402ClientSync:
        """The x402 core client the Agent Pay scheme is registered onto.

        For the Agent Pay HTTP API (``create_payment`` / ``get_payment`` /
        ``list_payments``) use :attr:`agent_pay_client`.
        """
        return self._x402_client

    @property
    def agent_pay_client(self) -> AgentPayClient:
        """The underlying Agent Pay transport client.

        Carries the direct API — ``create_payment``, plus ``get_payment`` and
        ``list_payments``, which are not part of the x402 buyer contract.
        """
        return self._client

    @property
    def scheme(self) -> AgentPayClientScheme:
        """The Agent Pay buyer scheme."""
        return self._scheme

    @property
    def registered_networks(self) -> set[str]:
        """Copy of the set of networks registered so far."""
        return set(self._registered_networks)

    def register_network(self, network: str) -> AgentPayClientBuilder:
        """Register a network for Agent Pay to handle.

        Wires the Agent Pay scheme into the underlying x402 client for this
        network, for **both** x402 v2 and v1. Registering v1 as well matters in
        practice: this SDK's own web middleware emits ``x402Version: 1`` in its
        402 responses, and x402 core dispatches v1 bodies through a separate
        registry. The Agent Pay payload is version-independent — the signed
        quote token is read from ``extra`` either way — so one scheme serves
        both.

        Returns ``self`` for chaining. Idempotent — re-registering the same
        network is a no-op.

        :param network: Network identifier (e.g., ``'aws:base'``). x402 core
            also accepts wildcard families such as ``'aws:*'``.
        """
        if network in self._registered_networks:
            return self
        self._registered_networks.add(network)
        self._x402_client.register(network, self._scheme)
        self._x402_client.register_v1(network, self._scheme)
        return self

    def create_payment_payload(
        self,
        payment_required: PaymentRequired | PaymentRequiredV1,
        resource: Any = None,
        extensions: Optional[dict[str, Any]] = None,
    ) -> PaymentPayload | PaymentPayloadV1:
        """Create a full x402 payment payload from a 402 response.

        Delegates to x402 core, which selects the matching requirements by
        network and scheme, dispatches to the Agent Pay scheme, and wraps the
        result into a complete ``PaymentPayload``.

        :param payment_required: The parsed 402 response body.
        :param resource: Optional resource info override.
        :param extensions: Optional extension data.
        :returns: The complete x402 payment payload.
        """
        return self._x402_client.create_payment_payload(payment_required, resource, extensions)

    def create_payment(self, **kwargs: Any) -> Any:
        """Shortcut: delegates to ``client.create_payment``.

        Bypasses x402 core entirely — useful when the caller already holds a
        quote token and does not need scheme selection.
        """
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

    client = AgentPayClient(
        base_url=base_url,
        authenticator=config.authenticator,
        credentials=config.credentials,
    )
    scheme = AgentPayClientScheme(
        agent_pay_id=config.agent_pay_id,
        agent_pay_client=client,
        dpop_jwk=config.dpop_jwk,
        client_token_generator=config.client_token_generator,
    )
    x402_client = config.existing_client or x402ClientSync()
    return AgentPayClientBuilder(client, scheme, x402_client)


def build_agent_pay_client(config: AgentPayClientConfig) -> x402ClientSync:
    """Convenience builder that creates and registers networks in one call.

    Returns the configured x402 client. Callers who also need the Agent Pay
    HTTP API should use :func:`create_agent_pay_client` and keep the builder,
    which exposes both via :attr:`~AgentPayClientBuilder.agent_pay_client`.

    :param config: Full client configuration including networks.
    :returns: Configured :class:`x402.x402ClientSync` with the Agent Pay scheme
        registered for every requested network.
    :raises ValidationError: if networks is empty or configuration is invalid.
    """
    if not config.networks:
        raise ValidationError("networks must be a non-empty array")

    builder = create_agent_pay_client(
        AgentPayClientOptions(
            agent_pay_id=config.agent_pay_id,
            agent_pay_base_url=config.agent_pay_base_url,
            authenticator=config.authenticator,
            credentials=config.credentials,
            dpop_jwk=config.dpop_jwk,
            client_token_generator=config.client_token_generator,
            existing_client=config.existing_client,
        )
    )

    for network in config.networks:
        builder.register_network(network)

    return builder.client


__all__ = [
    "AgentPayClientBuilder",
    "AgentPayClientConfig",
    "AgentPayClientOptions",
    "AgentPayConfig",
    "build_agent_pay_client",
    "create_agent_pay_client",
]
