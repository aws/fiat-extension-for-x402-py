# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helpers that register the ``exact`` scheme on x402 core objects."""

from __future__ import annotations

from typing import Optional, TypeVar

from fiat_extension_x402.agentic_commerce.exact.facilitator import (
    ExactAgenticCommerceScheme as ExactAgenticCommerceFacilitatorScheme,
)
from fiat_extension_x402.agentic_commerce.exact.server import (
    ExactAgenticCommerceScheme as ExactAgenticCommerceServerScheme,
)
from fiat_extension_x402.agentic_commerce.verifier import AgenticCommerceVerifier
from fiat_extension_x402.constants import DEFAULT_NETWORK
from fiat_extension_x402.signers.protocol import QuoteSigner

_Server = TypeVar("_Server")
_Facilitator = TypeVar("_Facilitator")


def register_exact_agentic_commerce_server(
    server: _Server,
    *,
    signer: QuoteSigner,
    networks: Optional[list[str]] = None,
) -> _Server:
    """Register the ``exact`` server scheme on an x402 resource server.

    :param server: ``x402ResourceServer`` or ``x402ResourceServerSync``.
    :param signer: Signs quote tokens.
    :param networks: Networks to register. Defaults to ``["aws:base"]``.
    :returns: ``server``, for chaining.
    """
    scheme = ExactAgenticCommerceServerScheme(signer=signer)
    for network in networks or [DEFAULT_NETWORK]:
        server.register(network, scheme)  # type: ignore[attr-defined]
    return server


def register_exact_agentic_commerce_facilitator(
    facilitator: _Facilitator,
    *,
    verifier: AgenticCommerceVerifier,
    networks: Optional[list[str]] = None,
) -> _Facilitator:
    """Register the ``exact`` facilitator scheme on an x402 facilitator.

    :param facilitator: ``x402Facilitator`` or ``x402FacilitatorSync``.
    :param verifier: Verifies payment tokens.
    :param networks: Networks to register. Defaults to ``["aws:base"]``.
    :returns: ``facilitator``, for chaining.
    """
    facilitator.register(  # type: ignore[attr-defined]
        networks or [DEFAULT_NETWORK],
        ExactAgenticCommerceFacilitatorScheme(verifier=verifier),
    )
    return facilitator


__all__ = [
    "register_exact_agentic_commerce_facilitator",
    "register_exact_agentic_commerce_server",
]
