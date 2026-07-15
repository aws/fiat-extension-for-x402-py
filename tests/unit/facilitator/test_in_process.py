# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for InProcessFacilitatorClient."""

from __future__ import annotations

from typing import Any

from fiat_extension_x402.facilitator import InProcessFacilitatorClient
from fiat_extension_x402.facilitator.types import SettleResponse, VerifyResponse


class TestInProcessFacilitatorClient:
    def test_verify_delegates(self) -> None:
        class MockFacilitator:
            def verify(
                self,
                payment_token: str,
                expected_quote_token: str,
                payment_requirements: dict[str, Any],
            ) -> VerifyResponse:
                return VerifyResponse(is_valid=True, payer="buyer")

        client = InProcessFacilitatorClient(MockFacilitator())
        result = client.verify("pt", "qt", {})
        assert result.is_valid is True
        assert result.payer == "buyer"

    def test_settle_delegates(self) -> None:
        class MockFacilitator:
            def settle(self, *, payment_id: str, network: str) -> SettleResponse:
                return SettleResponse(success=True, transaction=payment_id, network=network)

        client = InProcessFacilitatorClient(MockFacilitator())
        result = client.settle(payment_id="p1", network="aws:base")
        assert result.success is True
        assert result.transaction == "p1"

    def test_get_supported_delegates(self) -> None:
        class MockFacilitator:
            def get_supported(self) -> list[str]:
                return ["agent-pay"]

        client = InProcessFacilitatorClient(MockFacilitator())
        assert client.get_supported() == ["agent-pay"]

    def test_get_supported_missing(self) -> None:
        class MockFacilitator:
            pass

        client = InProcessFacilitatorClient(MockFacilitator())
        assert client.get_supported() is None
