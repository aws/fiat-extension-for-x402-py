# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for fiat_extension_x402.facilitator_scheme module.

The scheme adapts the verifier's positional arguments to the x402 facilitator
contract, so the interesting behaviour is the projection: which fields it pulls
out of the payload and requirements, and that invalid payments come back as a
``VerifyResponse`` rather than an exception.
"""

from __future__ import annotations

from typing import Any, Optional

from x402.schemas import PaymentPayload, PaymentRequirements, SettleResponse, VerifyResponse

from fiat_extension_x402.constants import (
    AGENT_PAY_CAIP_FAMILY,
    AGENT_PAY_SCHEME,
    AGENT_PAY_SENTINEL_PAY_TO,
)
from fiat_extension_x402.facilitator.types import SettleResponse as SdkSettleResponse
from fiat_extension_x402.facilitator.types import VerifyResponse as SdkVerifyResponse
from fiat_extension_x402.facilitator_scheme import AgentPayFacilitatorScheme

_PAYMENT_ID = "awsmp-00000000-0000-0000-0000-000000000001"
_QUOTE_TOKEN = "eyJ.quote.token"


class FakeVerifier:
    """Stands in for AgentPayFacilitatorClient, recording its arguments."""

    def __init__(self, *, is_valid: bool = True) -> None:
        self.is_valid = is_valid
        self.verify_calls: list[tuple[str, str, dict[str, Any], Optional[dict[str, Any]]]] = []
        self.settle_calls: list[tuple[str, str]] = []

    def verify(
        self,
        payment_token: str,
        expected_quote_token: str,
        payment_requirements: dict[str, Any],
        verify_options: Optional[dict[str, Any]] = None,
    ) -> SdkVerifyResponse:
        self.verify_calls.append(
            (payment_token, expected_quote_token, payment_requirements, verify_options)
        )
        if self.is_valid:
            return SdkVerifyResponse(is_valid=True, payer="111122223333")
        return SdkVerifyResponse(
            is_valid=False, invalid_reason="expired", invalid_message="Payment token expired"
        )

    def settle(self, *, payment_id: str, network: str) -> SdkSettleResponse:
        self.settle_calls.append((payment_id, network))
        return SdkSettleResponse(success=True, transaction=payment_id, network=network)


def _requirements(**overrides: Any) -> PaymentRequirements:
    base: dict[str, Any] = {
        "scheme": AGENT_PAY_SCHEME,
        "network": "aws:base",
        "asset": "iso4217:USD",
        "amount": "0.15",
        "payTo": AGENT_PAY_SENTINEL_PAY_TO,
        "maxTimeoutSeconds": 300,
        "extra": {"quoteToken": _QUOTE_TOKEN},
    }
    base.update(overrides)
    return PaymentRequirements.model_validate(base)


def _payload(inner: Optional[dict[str, Any]] = None, **kwargs: Any) -> PaymentPayload:
    return PaymentPayload(
        x402_version=2,
        payload=inner
        if inner is not None
        else {
            "paymentToken": "eyJ.payment.token",
            "paymentId": _PAYMENT_ID,
            "transactionId": _PAYMENT_ID,
        },
        accepted=_requirements(),
        **kwargs,
    )


class TestSchemeIdentity:
    def test_scheme_and_family(self) -> None:
        scheme = AgentPayFacilitatorScheme(client=FakeVerifier())
        assert scheme.scheme == AGENT_PAY_SCHEME
        assert scheme.caip_family == AGENT_PAY_CAIP_FAMILY

    def test_advertises_no_extras_or_signers_without_an_id(self) -> None:
        scheme = AgentPayFacilitatorScheme(client=FakeVerifier())
        assert scheme.get_extra("aws:base") is None
        assert scheme.get_signers("aws:base") == []

    def test_advertises_the_agent_pay_id_when_configured(self) -> None:
        """The supported-kinds response publishes agentPayId so clients can route."""
        scheme = AgentPayFacilitatorScheme(agent_pay_id="ap-1", client=FakeVerifier())
        assert scheme.agent_pay_id == "ap-1"
        assert scheme.get_extra("aws:base") == {"agentPayId": "ap-1"}
        assert scheme.get_signers("aws:base") == ["ap-1"]


class TestVerify:
    def test_projects_payload_and_requirements(self) -> None:
        fake = FakeVerifier()
        result = AgentPayFacilitatorScheme(client=fake).verify(_payload(), _requirements())

        assert isinstance(result, VerifyResponse)
        assert result.is_valid is True
        assert result.payer == "111122223333"

        token, quote, reqs, _ = fake.verify_calls[0]
        assert token == "eyJ.payment.token"
        assert quote == _QUOTE_TOKEN
        assert reqs == {"amount": "0.15", "asset": "iso4217:USD", "network": "aws:base"}

    def test_propagates_invalid_reason(self) -> None:
        result = AgentPayFacilitatorScheme(client=FakeVerifier(is_valid=False)).verify(
            _payload(), _requirements()
        )
        assert result.is_valid is False
        assert result.invalid_reason == "expired"
        assert result.invalid_message == "Payment token expired"

    def test_missing_payment_token_returns_invalid(self) -> None:
        """Contract is a VerifyResponse, never an exception."""
        fake = FakeVerifier()
        result = AgentPayFacilitatorScheme(client=fake).verify(
            _payload({"paymentId": _PAYMENT_ID}), _requirements()
        )
        assert result.is_valid is False
        assert result.invalid_reason == "invalid_payment"
        assert "paymentToken" in str(result.invalid_message)
        assert fake.verify_calls == []

    def test_missing_quote_token_returns_invalid(self) -> None:
        fake = FakeVerifier()
        result = AgentPayFacilitatorScheme(client=fake).verify(_payload(), _requirements(extra={}))
        assert result.is_valid is False
        assert result.invalid_reason == "invalid_payment"
        assert "quoteToken" in str(result.invalid_message)
        assert fake.verify_calls == []

    def test_forwards_default_verify_options(self) -> None:
        fake = FakeVerifier()
        options = {"dpop_proof": "proof", "method": "GET", "url": "https://api/x"}
        AgentPayFacilitatorScheme(client=fake, verify_options=options).verify(
            _payload(), _requirements()
        )
        assert fake.verify_calls[0][3] == options

    def test_per_request_extensions_override_defaults(self) -> None:
        """Per-request DPoP details ride in the agent-pay extensions entry."""
        fake = FakeVerifier()
        scheme = AgentPayFacilitatorScheme(
            client=fake, verify_options={"dpop_proof": "default", "method": "GET"}
        )
        scheme.verify(
            _payload(
                extensions={AGENT_PAY_SCHEME: {"dpop_proof": "per-call", "url": "https://api/y"}}
            ),
            _requirements(),
        )
        forwarded = fake.verify_calls[0][3]
        assert forwarded is not None
        assert forwarded["dpop_proof"] == "per-call"
        assert forwarded["url"] == "https://api/y"
        assert forwarded["method"] == "GET"  # default preserved

    def test_ignores_unrelated_extensions(self) -> None:
        fake = FakeVerifier()
        options = {"dpop_proof": "default"}
        AgentPayFacilitatorScheme(client=fake, verify_options=options).verify(
            _payload(extensions={"someOtherScheme": {"dpop_proof": "nope"}}), _requirements()
        )
        assert fake.verify_calls[0][3] == options


class TestSettle:
    def test_settles_with_the_payment_id(self) -> None:
        fake = FakeVerifier()
        result = AgentPayFacilitatorScheme(client=fake).settle(_payload(), _requirements())

        assert isinstance(result, SettleResponse)
        assert result.success is True
        assert result.transaction == _PAYMENT_ID
        assert result.network == "aws:base"
        assert fake.settle_calls == [(_PAYMENT_ID, "aws:base")]

    def test_falls_back_to_transaction_id(self) -> None:
        fake = FakeVerifier()
        AgentPayFacilitatorScheme(client=fake).settle(
            _payload({"paymentToken": "t", "transactionId": _PAYMENT_ID}), _requirements()
        )
        assert fake.settle_calls[0][0] == _PAYMENT_ID
