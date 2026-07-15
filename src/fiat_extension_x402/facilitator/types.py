# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Response types for the Agent Pay facilitator client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class VerifyResponse:
    """Result of payment verification.

    :param is_valid: Whether the payment passed all verification checks.
    :param payer: The payer identity (from the ``sub`` claim) when valid.
    :param invalid_reason: Machine-readable failure reason when invalid.
    :param invalid_message: Human-readable failure description when invalid.
    """

    is_valid: bool
    payer: Optional[str] = None
    invalid_reason: Optional[str] = None
    invalid_message: Optional[str] = None


@dataclass(frozen=True)
class SettleResponse:
    """Result of payment settlement.

    Agent Pay auto-captures on creation — settlement always succeeds.

    :param success: Always ``True`` for Agent Pay.
    :param transaction: The payment ID or transaction ID.
    :param network: The network from the payment requirements.
    """

    success: bool
    transaction: str
    network: str
