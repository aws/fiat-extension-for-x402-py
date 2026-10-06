# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helpers that register the ``exact`` scheme on x402 core objects."""

from __future__ import annotations

from typing import TypeVar

from fiat_extension_x402.agentic_commerce.exact.facilitator import (
    ExactAgenticCommerceScheme as ExactAgenticCommerceFacilitatorScheme,
)
from fiat_extension_x402.agentic_commerce.exact.server import (
    _DEFAULT_DPOP_MAX_AGE_SECONDS,
)
from fiat_extension_x402.agentic_commerce.exact.server import (
    ExactAgenticCommerceScheme as ExactAgenticCommerceServerScheme,
)
from fiat_extension_x402.agentic_commerce.verifier import AgenticCommerceVerifier
from fiat_extension_x402.constants import DEFAULT_NETWORK
from fiat_extension_x402.dpop import DPoPNonceStore
from fiat_extension_x402.signers.protocol import QuoteSigner

_Server = TypeVar("_Server")
_Facilitator = TypeVar("_Facilitator")


def register_exact_agentic_commerce_server(
    server: _Server,
    *,
    signer: QuoteSigner,
    networks: list[str] | None = None,
    dpop_nonce_store: DPoPNonceStore | None = None,
    dpop_max_age_seconds: int = _DEFAULT_DPOP_MAX_AGE_SECONDS,
) -> _Server:
    """Register the ``exact`` server scheme on an x402 resource server.

    :param server: ``x402ResourceServer`` or ``x402ResourceServerSync``.
    :param signer: Signs quote tokens.
    :param networks: Networks to register. Defaults to ``["aws:base"]``.
    :param dpop_nonce_store: Records DPoP proof ``jti`` values so a replayed
        proof is rejected. Use a store shared by all instances of the seller.
    :param dpop_max_age_seconds: Maximum age of a DPoP proof. Defaults to 60.
    :returns: ``server``, for chaining.
    """
    scheme = ExactAgenticCommerceServerScheme(
        signer=signer,
        dpop_nonce_store=dpop_nonce_store,
        dpop_max_age_seconds=dpop_max_age_seconds,
    )
    for network in networks or [DEFAULT_NETWORK]:
        server.register(network, scheme)  # type: ignore[attr-defined]
    return server


def register_exact_agentic_commerce_facilitator(
    facilitator: _Facilitator,
    *,
    verifier: AgenticCommerceVerifier,
    networks: list[str] | None = None,
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
