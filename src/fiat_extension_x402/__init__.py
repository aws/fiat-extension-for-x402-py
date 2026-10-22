# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fiat Extension for x402: AWS Marketplace Agentic Commerce schemes for x402.

Sellers register :class:`ExactAgenticCommerceServerScheme` on an x402 resource
server and :class:`ExactAgenticCommerceFacilitatorScheme` on an x402
facilitator, then protect routes with x402's own HTTP middleware.
"""

__version__ = "1.0.0"

from fiat_extension_x402.agentic_commerce import (
    AgenticCommerceVerifier,
    JwksSellerKeyResolver,
    KmsSellerKeyResolver,
    SellerKeyResolver,
    StaticSellerKeyResolver,
    VerificationResult,
    enhance_payment_requirements,
    jwks_document,
)
from fiat_extension_x402.agentic_commerce.exact import (
    ExactAgenticCommerceFacilitatorScheme,
    ExactAgenticCommerceServerScheme,
    register_exact_agentic_commerce_facilitator,
    register_exact_agentic_commerce_server,
)
from fiat_extension_x402.constants import (
    AGENTIC_COMMERCE_CAIP_FAMILY,
    DEFAULT_ASSET,
    DEFAULT_NETWORK,
    PAYMENT_TOKEN_ISSUER,
    SCHEME_EXACT,
    SENTINEL_PAY_TO,
)
from fiat_extension_x402.dpop import (
    DPoPNonceStore,
    DPoPVerificationOptions,
    compute_jwk_thumbprint,
    extract_dpop_thumbprint,
    verify_dpop_proof,
)
from fiat_extension_x402.exceptions import (
    AgenticCommerceError,
    DPoPError,
    SigningError,
    ValidationError,
)
from fiat_extension_x402.security import ALLOWED_ALGORITHMS, secure_compare
from fiat_extension_x402.signers import (
    KmsQuoteSigner,
    KmsQuoteSignerConfig,
    LocalQuoteSigner,
    QuoteSigner,
)
from fiat_extension_x402.utils import decode_quote_token

__all__ = [
    "AGENTIC_COMMERCE_CAIP_FAMILY",
    "ALLOWED_ALGORITHMS",
    "DEFAULT_ASSET",
    "DEFAULT_NETWORK",
    "PAYMENT_TOKEN_ISSUER",
    "SCHEME_EXACT",
    "SENTINEL_PAY_TO",
    "AgenticCommerceError",
    "AgenticCommerceVerifier",
    "DPoPError",
    "DPoPNonceStore",
    "DPoPVerificationOptions",
    "ExactAgenticCommerceFacilitatorScheme",
    "ExactAgenticCommerceServerScheme",
    "JwksSellerKeyResolver",
    "KmsQuoteSigner",
    "KmsQuoteSignerConfig",
    "KmsSellerKeyResolver",
    "LocalQuoteSigner",
    "QuoteSigner",
    "SellerKeyResolver",
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
    "register_exact_agentic_commerce_facilitator",
    "register_exact_agentic_commerce_server",
    "secure_compare",
    "verify_dpop_proof",
]
