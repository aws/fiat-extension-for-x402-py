# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Agent Pay facilitator scheme — the verification-side x402 mechanism.

In Agent Pay the facilitator role is played by the seller's verifier: it checks
that a payment token was really issued by Agent Pay for the quote the seller
issued, at the price the seller asked. (Agent Pay itself is the payment
authorizer; there is no separate facilitator service to run.)

This module adapts :class:`~fiat_extension_x402.facilitator.AgentPayFacilitatorClient`
to the x402 core facilitator contract
(:class:`x402.interfaces.SchemeNetworkFacilitator`), so verification can be
driven through the generic framework::

    from x402 import x402FacilitatorSync

    facilitator = x402FacilitatorSync()
    facilitator.register(["aws:base"], AgentPayFacilitatorScheme())
    response = facilitator.verify(payment_payload, requirements)

Unlike the underlying client — which takes the payment token, the expected quote
token, and a requirements dict as separate arguments — this scheme reads all
three out of the x402 ``PaymentPayload`` and ``PaymentRequirements``, which is
what makes it usable by core.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, Union, runtime_checkable

from x402.schemas import (
    PaymentPayload,
    PaymentPayloadV1,
    PaymentRequirements,
    PaymentRequirementsV1,
    SettleResponse,
    VerifyResponse,
)

from fiat_extension_x402.constants import AGENT_PAY_CAIP_FAMILY, AGENT_PAY_SCHEME
from fiat_extension_x402.facilitator.client import AgentPayFacilitatorClient
from fiat_extension_x402.facilitator.types import SettleResponse as SdkSettleResponse
from fiat_extension_x402.facilitator.types import VerifyResponse as SdkVerifyResponse

_AnyPayload = Union[PaymentPayload, PaymentPayloadV1]
_AnyRequirements = Union[PaymentRequirements, PaymentRequirementsV1]


@runtime_checkable
class AgentPayVerifier(Protocol):
    """The verification contract this scheme depends on.

    Narrow by design, so a test double or an alternative verifier can stand in
    for :class:`AgentPayFacilitatorClient` without subclassing it.
    """

    def verify(
        self,
        payment_token: str,
        expected_quote_token: str,
        payment_requirements: dict[str, Any],
        verify_options: Optional[dict[str, Any]] = None,
    ) -> SdkVerifyResponse:
        """Check a payment token against the quote it claims to satisfy."""
        ...

    def settle(self, *, payment_id: str, network: str) -> SdkSettleResponse:
        """Settle a payment (a no-op for Agent Pay, which auto-captures)."""
        ...


class AgentPayFacilitatorScheme:
    """Agent Pay verifier satisfying x402 core's ``SchemeNetworkFacilitator``.

    :param agent_pay_id: Agent Pay identifier for this facilitator. Advertised in
        the supported-kinds response via :meth:`get_extra` and
        :meth:`get_signers`, so clients can route on it.
    :param client: Verifier to delegate to — anything satisfying
        :class:`AgentPayVerifier`. Defaults to a stock
        :class:`AgentPayFacilitatorClient` (production Agent Pay JWKS).
    :param verify_options: Default options forwarded to every ``verify`` call —
        for example a DPoP proof and the request's method/URL. Individual calls
        can override these via the payload's ``extra`` (see :meth:`verify`).
    """

    def __init__(
        self,
        *,
        agent_pay_id: Optional[str] = None,
        client: Optional[AgentPayVerifier] = None,
        verify_options: Optional[dict[str, Any]] = None,
    ) -> None:
        self._agent_pay_id = agent_pay_id
        self._client: AgentPayVerifier = (
            client if client is not None else AgentPayFacilitatorClient()
        )
        self._verify_options = verify_options

    @property
    def scheme(self) -> str:
        """x402 scheme identifier handled by this facilitator (``agent-pay``)."""
        return AGENT_PAY_SCHEME

    @property
    def caip_family(self) -> str:
        """CAIP family this facilitator serves (``aws:*``)."""
        return AGENT_PAY_CAIP_FAMILY

    @property
    def agent_pay_id(self) -> Optional[str]:
        """The configured Agent Pay identifier, if any."""
        return self._agent_pay_id

    @property
    def client(self) -> AgentPayVerifier:
        """The underlying verifier."""
        return self._client

    def get_extra(self, network: str) -> dict[str, Any] | None:
        """Return scheme extras for the supported-kinds response.

        Advertises the configured ``agentPayId`` so clients can route on it.
        Returns ``None`` when no identifier was configured, since there is
        nothing meaningful to publish.
        """
        if self._agent_pay_id is None:
            return None
        return {"agentPayId": self._agent_pay_id}

    def get_signers(self, network: str) -> list[str]:
        """Return signer addresses for this network.

        Agent Pay authorizes payments against the buyer's AWS account rather
        than a wallet address, so the Agent Pay identifier stands in as the
        signer. Empty when no identifier was configured.
        """
        if self._agent_pay_id is None:
            return []
        return [self._agent_pay_id]

    def verify(
        self,
        payload: _AnyPayload,
        requirements: _AnyRequirements,
        context: Any = None,
    ) -> VerifyResponse:
        """Verify an Agent Pay payment against the requirements it satisfies.

        Reads the payment token from ``payload.payload["paymentToken"]`` and the
        expected quote token from ``requirements.extra["quoteToken"]`` — the
        quote the seller signed. Per-request DPoP details may be supplied under
        the ``agent-pay`` key of ``payload.extensions`` (see
        :meth:`_resolve_verify_options`).

        Never raises for an invalid payment: failures come back as a
        ``VerifyResponse`` with ``is_valid=False`` and an ``invalid_reason``,
        which is the x402 facilitator contract.

        :param payload: The buyer's x402 payment payload.
        :param requirements: The requirements being satisfied.
        :param context: Facilitator context. Unused by Agent Pay.
        :returns: The verification outcome.
        """
        inner = payload.payload or {}
        payment_token = inner.get("paymentToken")
        if not payment_token:
            return VerifyResponse(
                is_valid=False,
                invalid_reason="invalid_payment",
                invalid_message="Missing paymentToken in payment payload",
            )

        extra = requirements.extra or {}
        expected_quote_token = extra.get("quoteToken")
        if not expected_quote_token:
            return VerifyResponse(
                is_valid=False,
                invalid_reason="invalid_payment",
                invalid_message="Missing quoteToken in payment requirements",
            )

        verify_options = self._resolve_verify_options(payload)

        result = self._client.verify(
            str(payment_token),
            str(expected_quote_token),
            self._verify_requirements(requirements),
            verify_options=verify_options,
        )
        # The SDK's VerifyResponse is a distinct dataclass from x402 core's
        # model, so translate rather than pass it through.
        return VerifyResponse(
            is_valid=result.is_valid,
            invalid_reason=result.invalid_reason,
            invalid_message=result.invalid_message,
            payer=result.payer,
        )

    def settle(
        self,
        payload: _AnyPayload,
        requirements: _AnyRequirements,
        context: Any = None,
    ) -> SettleResponse:
        """Settle a payment — a no-op for Agent Pay.

        Agent Pay auto-captures funds when the payment is created, so there is
        no separate capture step. Returns success with the payment id as the
        transaction reference, matching the standalone client.

        :param payload: The buyer's x402 payment payload.
        :param requirements: The requirements being settled.
        :param context: Facilitator context. Unused by Agent Pay.
        :returns: A successful settlement referencing the payment id.
        """
        inner = payload.payload or {}
        payment_id = inner.get("paymentId") or inner.get("transactionId") or ""
        network = getattr(requirements, "network", "") or ""
        result = self._client.settle(payment_id=str(payment_id), network=str(network))
        # Translate the SDK's dataclass into x402 core's model.
        return SettleResponse(
            success=result.success,
            transaction=result.transaction,
            network=result.network,
        )

    def _resolve_verify_options(self, payload: _AnyPayload) -> Optional[dict[str, Any]]:
        """Merge the scheme's default verify options with per-request overrides.

        A DPoP-bound payment needs the proof plus the method and URL it was bound
        to, and those are per-request — the same scheme instance serves every
        request. x402 core carries no per-call slot for them on the v2 payload
        (``PaymentPayload`` has no ``extra``), so they are read from the
        ``agent-pay`` entry of ``payload.extensions``::

            PaymentPayload(..., extensions={"agent-pay": {
                "dpop_proof": proof, "method": "GET", "url": request_url}})

        Anything not supplied per request falls back to the scheme defaults.
        """
        extensions = getattr(payload, "extensions", None) or {}
        per_call = extensions.get(AGENT_PAY_SCHEME) or {}
        if not isinstance(per_call, dict):
            return self._verify_options
        overrides = {
            key: per_call[key] for key in ("dpop_proof", "method", "url") if key in per_call
        }
        if not overrides:
            return self._verify_options
        return {**(self._verify_options or {}), **overrides}

    @staticmethod
    def _verify_requirements(requirements: _AnyRequirements) -> dict[str, Any]:
        """Project x402 requirements onto the dict the verifier expects.

        v1 carries the price in ``maxAmountRequired``; v2 uses ``amount``.
        """
        amount = getattr(requirements, "amount", None)
        if amount is None:
            amount = getattr(requirements, "max_amount_required", None)
        return {
            "amount": amount,
            "asset": requirements.asset,
            "network": requirements.network,
        }


__all__ = ["AgentPayFacilitatorScheme", "AgentPayVerifier"]
