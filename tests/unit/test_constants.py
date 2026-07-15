# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for constants module."""

from __future__ import annotations

from fiat_extension_x402.constants import (
    AGENT_PAY_AUDIENCE,
    AGENT_PAY_CAIP_FAMILY,
    AGENT_PAY_SCHEME,
    AGENT_PAY_SENTINEL_PAY_TO,
    DEFAULT_PAYMENT_VALIDITY_SECONDS,
    DEFAULT_QUOTE_VALIDITY_SECONDS,
    SETTLEMENT_CYCLES,
    SETTLEMENT_METHODS,
)


def test_agent_pay_scheme_value() -> None:
    assert AGENT_PAY_SCHEME == "agent-pay"


def test_default_payment_validity() -> None:
    assert DEFAULT_PAYMENT_VALIDITY_SECONDS == 3600


def test_audience_value() -> None:
    assert AGENT_PAY_AUDIENCE == "aws:marketplace"


def test_sentinel_pay_to_value() -> None:
    assert AGENT_PAY_SENTINEL_PAY_TO == "urn:x402:agent-pay:see-quote"


def test_default_quote_validity() -> None:
    assert DEFAULT_QUOTE_VALIDITY_SECONDS == 300


class TestNewConstants:
    def test_caip_family(self) -> None:
        assert AGENT_PAY_CAIP_FAMILY == "aws:*"

    def test_settlement_methods(self) -> None:
        assert SETTLEMENT_METHODS == {"INST": "INST", "CLRG": "CLRG", "CRDT": "CRDT"}

    def test_settlement_cycles(self) -> None:
        assert SETTLEMENT_CYCLES == {"MNTH": "MNTH", "WEEK": "WEEK", "QRTR": "QRTR"}
