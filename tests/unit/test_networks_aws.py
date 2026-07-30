# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the AWS-preconfigured Agent Pay schemes."""

from __future__ import annotations

from typing import Any

from fiat_extension_x402.constants import (
    AGENT_PAY_CAIP_FAMILY,
    AGENT_PAY_SCHEME,
    DEFAULT_AGENT_PAY_BASE_URL,
)
from fiat_extension_x402.networks import (
    AgentPayAWSClientScheme,
    AgentPayAWSFacilitatorScheme,
    AgentPayAWSServerScheme,
)


class FakeSigner:
    async def sign_quote(self, payload: dict[str, Any]) -> str:
        return "eyJ.signed.quote"

    def get_public_key(self) -> object:
        return {}

    def get_service_url(self) -> str:
        return "https://seller.example.com"


class TestAgentPayAWSClientScheme:
    def test_pins_the_production_endpoint(self) -> None:
        scheme = AgentPayAWSClientScheme(agent_pay_id="111122223333")
        assert scheme.scheme == AGENT_PAY_SCHEME
        assert scheme.agent_pay_id == "111122223333"
        # The transport it built targets the AWS Marketplace endpoint.
        assert scheme._agent_pay_client._base_url == DEFAULT_AGENT_PAY_BASE_URL  # type: ignore[attr-defined]


class TestAgentPayAWSServerScheme:
    def test_exposes_scheme_and_family(self) -> None:
        scheme = AgentPayAWSServerScheme(signer=FakeSigner())
        assert scheme.scheme == AGENT_PAY_SCHEME
        assert scheme.caip_family == AGENT_PAY_CAIP_FAMILY

    def test_parses_price_like_the_base_scheme(self) -> None:
        result = AgentPayAWSServerScheme(signer=FakeSigner()).parse_price("$1.50", "aws:base")
        assert (result.amount, result.asset) == ("1.5", "iso4217:USD")


class TestAgentPayAWSFacilitatorScheme:
    def test_defaults_its_agent_pay_id(self) -> None:
        scheme = AgentPayAWSFacilitatorScheme()
        assert scheme.agent_pay_id == "aws-agent-pay"
        assert scheme.get_extra("aws:base") == {"agentPayId": "aws-agent-pay"}
        assert scheme.get_signers("aws:base") == ["aws-agent-pay"]

    def test_accepts_an_explicit_id(self) -> None:
        scheme = AgentPayAWSFacilitatorScheme(agent_pay_id="custom")
        assert scheme.get_signers("aws:base") == ["custom"]
