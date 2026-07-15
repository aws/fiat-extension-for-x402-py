# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""In-process facilitator client that wraps a facilitator object.

Used for development and testing when a real HTTP-based facilitator is not
needed.
"""

from __future__ import annotations

from typing import Any

from fiat_extension_x402.facilitator.types import SettleResponse, VerifyResponse


class InProcessFacilitatorClient:
    """Facilitator client that delegates to an in-process facilitator object.

    The wrapped facilitator must implement ``verify`` and ``settle`` methods
    with the same signatures as :class:`AgentPayFacilitatorClient`.

    :param facilitator: Object implementing verify/settle methods.
    """

    def __init__(self, facilitator: Any) -> None:
        self._facilitator = facilitator

    def verify(
        self,
        payment_token: str,
        expected_quote_token: str,
        payment_requirements: dict[str, Any],
    ) -> VerifyResponse:
        """Delegate verification to the wrapped facilitator."""
        result: VerifyResponse = self._facilitator.verify(
            payment_token, expected_quote_token, payment_requirements
        )
        return result

    def settle(self, *, payment_id: str, network: str) -> SettleResponse:
        """Delegate settlement to the wrapped facilitator."""
        result: SettleResponse = self._facilitator.settle(payment_id=payment_id, network=network)
        return result

    def get_supported(self) -> Any:
        """Delegate get_supported to the wrapped facilitator, if available."""
        if hasattr(self._facilitator, "get_supported"):
            return self._facilitator.get_supported()
        return None


__all__ = ["InProcessFacilitatorClient"]
