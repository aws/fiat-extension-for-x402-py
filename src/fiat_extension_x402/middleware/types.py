# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Framework-agnostic middleware types shared by the Flask and FastAPI middleware.

These dataclasses carry no web-framework imports so they can be used without
installing Flask or FastAPI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class AgentPayRouteConfig:
    """Per-route payment configuration.

    :param price: Price for this route (e.g., ``0.15``).
    :param network: Network to use (e.g., ``'aws:base'``).
    :param pay_to: Recipient Agent Pay ID.
    :param asset: Asset identifier (e.g., ``'iso4217:USD'``).
    :param description: Human-readable description of what is being charged for.
    :param dimensions: Key-value dimensions describing units consumed.
    :param mime_type: MIME type of the protected resource.
    :param extra: Extra fields to include in the quote token.
    """

    price: Any
    network: str
    pay_to: str
    asset: str = "iso4217:USD"
    description: Optional[str] = None
    dimensions: Optional[dict[str, Any]] = None
    mime_type: Optional[str] = None
    extra: Optional[dict[str, Any]] = None


@dataclass(frozen=True)
class PaymentInfo:
    """Payment information attached to the request after verification.

    :param payer: Payer identity (from payment token).
    :param transaction_id: Transaction ID.
    :param network: Network used.
    :param amount: Amount paid.
    :param asset: Asset (e.g., ``'iso4217:USD'``).
    """

    payer: str
    transaction_id: str
    network: str
    amount: str
    asset: str


__all__ = ["AgentPayRouteConfig", "PaymentInfo"]
