# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the package's public API surface."""

from __future__ import annotations

import importlib

import pytest

import fiat_extension_x402

EXPECTED_EXPORTS = {
    "AGENTIC_COMMERCE_CAIP_FAMILY",
    "ALLOWED_ALGORITHMS",
    "AgenticCommerceError",
    "AgenticCommerceVerifier",
    "DEFAULT_ASSET",
    "DEFAULT_NETWORK",
    "DPoPError",
    "DPoPNonceStore",
    "DPoPVerificationOptions",
    "ExactAgenticCommerceFacilitatorScheme",
    "ExactAgenticCommerceServerScheme",
    "ExpiryError",
    "JwksSellerKeyResolver",
    "KmsQuoteSigner",
    "KmsQuoteSignerConfig",
    "KmsSellerKeyResolver",
    "LocalQuoteSigner",
    "MismatchError",
    "PAYMENT_TOKEN_ISSUER",
    "QuoteSigner",
    "SCHEME_EXACT",
    "SENTINEL_PAY_TO",
    "SellerKeyResolver",
    "SignatureError",
    "SigningError",
    "StaticSellerKeyResolver",
    "ValidationError",
    "VerificationResult",
    "__version__",
    "compute_jwk_thumbprint",
    "decode_quote_token",
    "enhance_payment_requirements",
    "extract_dpop_thumbprint",
    "jwks_document",
    "parse_money_to_decimal",
    "register_exact_agentic_commerce_facilitator",
    "register_exact_agentic_commerce_server",
    "secure_compare",
    "validate_url",
    "verify_dpop_proof",
    "verify_payment_token",
    "verify_quote_token",
}

SUBMODULES = [
    "fiat_extension_x402.agentic_commerce",
    "fiat_extension_x402.agentic_commerce.exact",
    "fiat_extension_x402.constants",
    "fiat_extension_x402.dpop",
    "fiat_extension_x402.exceptions",
    "fiat_extension_x402.security",
    "fiat_extension_x402.signers",
    "fiat_extension_x402.utils",
]


def test_all_matches_expected_exports() -> None:
    assert set(fiat_extension_x402.__all__) == EXPECTED_EXPORTS
    assert len(fiat_extension_x402.__all__) == len(EXPECTED_EXPORTS)


@pytest.mark.parametrize("name", sorted(EXPECTED_EXPORTS))
def test_export_is_importable(name: str) -> None:
    assert getattr(fiat_extension_x402, name) is not None


def test_version() -> None:
    assert fiat_extension_x402.__version__ == "1.0.0"


def test_constant_values() -> None:
    assert fiat_extension_x402.SCHEME_EXACT == "exact"
    assert fiat_extension_x402.AGENTIC_COMMERCE_CAIP_FAMILY == "aws:*"
    assert fiat_extension_x402.DEFAULT_NETWORK == "aws:base"
    assert fiat_extension_x402.DEFAULT_ASSET == "iso4217:USD"


@pytest.mark.parametrize("module_name", SUBMODULES)
def test_submodule_all_names_resolve(module_name: str) -> None:
    module = importlib.import_module(module_name)
    for name in module.__all__:
        assert hasattr(module, name), f"{module_name}.{name}"
