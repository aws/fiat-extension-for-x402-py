# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the registration helpers."""

from __future__ import annotations

from x402 import x402Facilitator, x402FacilitatorSync, x402ResourceServer, x402ResourceServerSync

from fiat_extension_x402.agentic_commerce import AgenticCommerceVerifier, StaticSellerKeyResolver
from fiat_extension_x402.agentic_commerce.exact import (
    ExactAgenticCommerceFacilitatorScheme,
    ExactAgenticCommerceServerScheme,
    register_exact_agentic_commerce_facilitator,
    register_exact_agentic_commerce_server,
)
from tests.support import seller_signer


def _verifier() -> AgenticCommerceVerifier:
    return AgenticCommerceVerifier(
        seller_key_resolver=StaticSellerKeyResolver(seller_signer().public_jwk)
    )


def _supported(facilitator: x402FacilitatorSync | x402Facilitator) -> set[tuple[str, str]]:
    return {(kind.scheme, kind.network) for kind in facilitator.get_supported().kinds}


class TestRegisterServer:
    def test_default_network(self) -> None:
        signer = seller_signer()
        server = x402ResourceServerSync()
        assert register_exact_agentic_commerce_server(server, signer=signer) is server
        assert server.has_registered_scheme("aws:base", "exact")
        scheme = server._schemes["aws:base"]["exact"]
        assert isinstance(scheme, ExactAgenticCommerceServerScheme)
        assert scheme.signer is signer

    def test_custom_networks(self) -> None:
        server = x402ResourceServerSync()
        register_exact_agentic_commerce_server(
            server, signer=seller_signer(), networks=["aws:one", "aws:two"]
        )
        assert server.has_registered_scheme("aws:one", "exact")
        assert server.has_registered_scheme("aws:two", "exact")
        assert not server.has_registered_scheme("aws:base", "exact")

    def test_async_server(self) -> None:
        server = x402ResourceServer()
        assert register_exact_agentic_commerce_server(server, signer=seller_signer()) is server
        assert server.has_registered_scheme("aws:base", "exact")


class TestRegisterFacilitator:
    def test_default_network(self) -> None:
        verifier = _verifier()
        facilitator = x402FacilitatorSync()
        assert (
            register_exact_agentic_commerce_facilitator(facilitator, verifier=verifier)
            is facilitator
        )
        assert _supported(facilitator) == {("exact", "aws:base")}
        scheme = facilitator._schemes[0].facilitator
        assert isinstance(scheme, ExactAgenticCommerceFacilitatorScheme)
        assert scheme.verifier is verifier

    def test_custom_networks(self) -> None:
        facilitator = x402FacilitatorSync()
        register_exact_agentic_commerce_facilitator(
            facilitator, verifier=_verifier(), networks=["aws:one", "aws:two"]
        )
        assert _supported(facilitator) == {("exact", "aws:one"), ("exact", "aws:two")}

    def test_async_facilitator(self) -> None:
        facilitator = x402Facilitator()
        register_exact_agentic_commerce_facilitator(facilitator, verifier=_verifier())
        assert _supported(facilitator) == {("exact", "aws:base")}
        assert facilitator.get_supported().signers == {"aws:*": []}
