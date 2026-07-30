# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Agent Pay client scheme — the buyer-side x402 payment mechanism.

In Agent Pay, the "client" role is played by the AI agent (buyer), which sends
the seller's quote token to the Agent Pay Service and receives a signed payment
JWT in return.

This module adapts that exchange to the x402 core client contract
(:class:`x402.interfaces.SchemeNetworkClient`), so an Agent Pay payment can be
created through the generic framework entry point::

    from x402 import x402ClientSync

    client = x402ClientSync()
    client.register("aws:base", AgentPayClientScheme(agent_pay_id="...", ...))
    payload = client.create_payment_payload(payment_required)

The scheme returns only the *inner* payload dict; x402 core wraps it into a full
``PaymentPayload`` (adding ``x402Version``, ``accepted``, ``resource`` and
``extensions``).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Optional

from botocore.credentials import Credentials  # type: ignore[import-untyped]
from x402.schemas import PaymentRequirements, PaymentRequirementsV1

from fiat_extension_x402.auth import Authenticator
from fiat_extension_x402.client import AgentPayClient, AgentPayClientForClient
from fiat_extension_x402.constants import AGENT_PAY_SCHEME, DEFAULT_AGENT_PAY_BASE_URL
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.schemas import (
    AgentPayPayloadV2,
    CreateAgentPaymentRequest,
    DpopJwk,
)


@dataclass
class AgentPayConfig:
    """Agent Pay endpoint configuration.

    Used when the scheme should build its own transport instead of receiving a
    pre-constructed client.

    :param base_url: Agent Pay service base URL. Defaults to production.
    :param authenticator: Authenticator used to sign outgoing requests.
    :param credentials: AWS credentials for SigV4 signing (mutually exclusive
        with ``authenticator``).
    """

    base_url: str = DEFAULT_AGENT_PAY_BASE_URL
    authenticator: Optional[Authenticator] = None
    credentials: Optional[Credentials] = None


class AgentPayClientScheme:
    """Agent Pay buyer scheme satisfying x402 core's ``SchemeNetworkClient``.

    Sends quote tokens to the Agent Pay Service and returns the resulting
    payment token as an x402 payload.

    Provide **either** ``agent_pay_client`` (any object implementing
    :class:`~fiat_extension_x402.client.AgentPayClientForClient`) **or**
    ``agent_pay`` configuration. If both are given, ``agent_pay_client`` wins.

    :param agent_pay_id: Agent Pay identifier for this buyer.
    :param agent_pay_client: Pre-built buyer client to use for ``create_payment``.
    :param agent_pay: Configuration from which to build a default client.
    :param dpop_jwk: Optional DPoP public key to bind payment tokens to.
    :param client_token_generator: Optional idempotency-key factory. Defaults to
        a fresh UUID4 per call.
    :raises ValidationError: if neither ``agent_pay_client`` nor ``agent_pay``
        is provided.
    """

    def __init__(
        self,
        *,
        agent_pay_id: str,
        agent_pay_client: Optional[AgentPayClientForClient] = None,
        agent_pay: Optional[AgentPayConfig] = None,
        dpop_jwk: Optional[DpopJwk] = None,
        client_token_generator: Optional[Callable[[], str]] = None,
    ) -> None:
        self._agent_pay_id = agent_pay_id
        self._dpop_jwk = dpop_jwk
        self._client_token_generator = client_token_generator

        if agent_pay_client is not None:
            self._agent_pay_client: AgentPayClientForClient = agent_pay_client
        elif agent_pay is not None:
            self._agent_pay_client = AgentPayClient(
                base_url=agent_pay.base_url,
                authenticator=agent_pay.authenticator,
                credentials=agent_pay.credentials,
            )
        else:
            raise ValidationError(
                "AgentPayClientScheme requires either agent_pay_client or Agent Pay configuration"
            )

    @property
    def scheme(self) -> str:
        """x402 scheme identifier handled by this client (``agent-pay``)."""
        return AGENT_PAY_SCHEME

    @property
    def agent_pay_id(self) -> str:
        """The configured Agent Pay identifier."""
        return self._agent_pay_id

    def create_payment_payload(
        self, requirements: PaymentRequirements | PaymentRequirementsV1
    ) -> dict[str, Any]:
        """Create the Agent Pay inner payload for a set of payment requirements.

        Sends the quote token to the Agent Pay Service, which verifies the
        quote, captures the payment, and returns a signed payment JWT. The
        service derives every payment detail (amount, currency, recipient) from
        the signed quote token, so only the token is forwarded — the outer
        ``amount``/``asset``/``payTo`` fields are deliberately not sent.

        Accepts both x402 v2 and v1 requirements: the Agent Pay payload is
        version-independent because everything needed is inside the signed
        quote token, which both shapes carry in ``extra``. This lets one scheme
        instance serve v2 and v1 sellers alike — including this SDK's own
        middleware, which emits ``x402Version: 1``.

        :param requirements: The x402 payment requirements being fulfilled. The
            seller's quote token is read from ``extra["quoteToken"]``.
        :returns: The scheme-specific payload dict. x402 core wraps this into a
            full ``PaymentPayload`` (or ``PaymentPayloadV1``).
        :raises ValidationError: if the requirements carry no quote token.
        """
        extra = requirements.extra or {}
        quote_token = extra.get("quoteToken")
        if not quote_token:
            raise ValidationError("Missing quoteToken in payment requirements")

        # A fresh idempotency key per call: replaying the same requirements is a
        # new payment, not a replay of the previous one.
        client_token = (
            self._client_token_generator()
            if self._client_token_generator is not None
            else str(uuid.uuid4())
        )

        result = self._agent_pay_client.create_payment(
            CreateAgentPaymentRequest(
                quote_token=quote_token,
                client_token=client_token,
                dpop_jwk=self._dpop_jwk,
            )
        )

        payload = AgentPayPayloadV2(
            payment_token=result.payment_token,
            payment_id=result.payment_id,
            # Back-compat alias for pre-v2 verifiers; always equal to payment_id.
            transaction_id=result.payment_id,
        )
        return payload.model_dump(by_alias=True, exclude_none=True)


__all__ = ["AgentPayClientScheme", "AgentPayConfig"]
