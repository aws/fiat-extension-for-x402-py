# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for fiat_extension_x402.client_scheme module.

These exercise the buyer scheme against a fake ``AgentPayClientForClient``
rather than mocking HTTP: the transport itself is covered by
``tests/unit/test_client.py``. What matters here is the x402 contract — the
exact inner payload dict, the quote-token requirement, and that nothing beyond
the quote token reaches the Agent Pay service.
"""

from __future__ import annotations

from typing import Any

import pytest
from x402.schemas import PaymentRequirements

from fiat_extension_x402.client_scheme import AgentPayClientScheme, AgentPayConfig
from fiat_extension_x402.constants import AGENT_PAY_SCHEME, AGENT_PAY_SENTINEL_PAY_TO
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.schemas import (
    CreateAgentPaymentRequest,
    CreateAgentPaymentResponse,
    DpopJwk,
)

_PAYMENT_ID = "awsmp-00000000-0000-0000-0000-000000000001"
_QUOTE_TOKEN = "eyJ.quote.token"


class FakeBuyerClient:
    """Minimal ``AgentPayClientForClient`` that records what it was sent."""

    def __init__(self, payment_id: str = _PAYMENT_ID) -> None:
        self.payment_id = payment_id
        self.requests: list[CreateAgentPaymentRequest] = []

    def create_payment(self, request: CreateAgentPaymentRequest) -> CreateAgentPaymentResponse:
        self.requests.append(request)
        return CreateAgentPaymentResponse.model_validate(
            {
                "paymentId": self.payment_id,
                "paymentToken": "eyJ.payment.token",
                "createdAt": "2026-07-28T00:00:00Z",
            }
        )


def _requirements(**overrides: Any) -> PaymentRequirements:
    """Build agent-pay payment requirements, quote token included by default."""
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


def _scheme(client: FakeBuyerClient | None = None, **kwargs: Any) -> AgentPayClientScheme:
    return AgentPayClientScheme(
        agent_pay_id="agent-pay-test",
        agent_pay_client=client or FakeBuyerClient(),
        **kwargs,
    )


class TestSchemeIdentity:
    def test_scheme_is_agent_pay(self) -> None:
        assert _scheme().scheme == AGENT_PAY_SCHEME

    def test_exposes_agent_pay_id(self) -> None:
        assert _scheme().agent_pay_id == "agent-pay-test"


class TestConstruction:
    def test_requires_client_or_config(self) -> None:
        with pytest.raises(ValidationError, match="requires either agent_pay_client"):
            AgentPayClientScheme(agent_pay_id="agent-pay-test")

    def test_accepts_agent_pay_config(self) -> None:
        scheme = AgentPayClientScheme(
            agent_pay_id="agent-pay-test",
            agent_pay=AgentPayConfig(base_url="https://custom.example.com"),
        )
        assert scheme.scheme == AGENT_PAY_SCHEME

    def test_explicit_client_wins_over_config(self) -> None:
        """An explicit client takes precedence over endpoint configuration."""
        fake = FakeBuyerClient()
        scheme = AgentPayClientScheme(
            agent_pay_id="agent-pay-test",
            agent_pay_client=fake,
            agent_pay=AgentPayConfig(base_url="https://ignored.example.com"),
        )
        scheme.create_payment_payload(_requirements())
        assert len(fake.requests) == 1


class TestCreatePaymentPayload:
    def test_returns_inner_payload_dict(self) -> None:
        """x402 core adds x402Version/accepted; the scheme returns only the payload."""
        payload = _scheme().create_payment_payload(_requirements())
        assert payload == {
            "paymentToken": "eyJ.payment.token",
            "paymentId": _PAYMENT_ID,
            "transactionId": _PAYMENT_ID,
        }

    def test_does_not_set_x402_version(self) -> None:
        assert "x402Version" not in _scheme().create_payment_payload(_requirements())

    def test_transaction_id_equals_payment_id(self) -> None:
        """transactionId is a deprecated alias kept for pre-v2 verifiers."""
        payload = _scheme().create_payment_payload(_requirements())
        assert payload["transactionId"] == payload["paymentId"]

    def test_forwards_quote_token(self) -> None:
        fake = FakeBuyerClient()
        _scheme(fake).create_payment_payload(_requirements())
        assert fake.requests[0].quote_token == _QUOTE_TOKEN

    def test_sends_nothing_but_the_quote(self) -> None:
        """amount/asset/payTo are authoritative in the signed quote, so are not sent."""
        fake = FakeBuyerClient()
        _scheme(fake).create_payment_payload(
            _requirements(amount="999.99", asset="iso4217:EUR", payTo="attacker")
        )
        sent = fake.requests[0].model_dump(by_alias=True, exclude_none=True)
        assert set(sent) == {"quoteToken", "clientToken"}


class TestQuoteTokenValidation:
    def test_missing_quote_token_raises(self) -> None:
        with pytest.raises(ValidationError, match="Missing quoteToken in payment requirements"):
            _scheme().create_payment_payload(_requirements(extra={}))

    def test_empty_quote_token_raises(self) -> None:
        with pytest.raises(ValidationError, match="Missing quoteToken in payment requirements"):
            _scheme().create_payment_payload(_requirements(extra={"quoteToken": ""}))

    def test_no_payment_attempted_when_quote_missing(self) -> None:
        fake = FakeBuyerClient()
        with pytest.raises(ValidationError):
            _scheme(fake).create_payment_payload(_requirements(extra={}))
        assert fake.requests == []


class TestClientToken:
    def test_generates_a_client_token(self) -> None:
        fake = FakeBuyerClient()
        _scheme(fake).create_payment_payload(_requirements())
        assert fake.requests[0].client_token

    def test_client_token_is_fresh_per_call(self) -> None:
        """Replaying the same requirements creates a new payment."""
        fake = FakeBuyerClient()
        scheme = _scheme(fake)
        scheme.create_payment_payload(_requirements())
        scheme.create_payment_payload(_requirements())
        assert fake.requests[0].client_token != fake.requests[1].client_token

    def test_honors_injected_generator(self) -> None:
        fake = FakeBuyerClient()
        scheme = _scheme(fake, client_token_generator=lambda: "fixed-token")
        scheme.create_payment_payload(_requirements())
        assert fake.requests[0].client_token == "fixed-token"


class TestDpopBinding:
    def test_dpop_omitted_by_default(self) -> None:
        fake = FakeBuyerClient()
        _scheme(fake).create_payment_payload(_requirements())
        assert fake.requests[0].dpop_jwk is None

    def test_dpop_forwarded_when_configured(self) -> None:
        jwk = DpopJwk.model_validate(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            }
        )
        fake = FakeBuyerClient()
        _scheme(fake, dpop_jwk=jwk).create_payment_payload(_requirements())
        assert fake.requests[0].dpop_jwk == jwk
