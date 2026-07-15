# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""DPoP (Demonstrating Proof-of-Possession) module.

Provides key generation, JWK conversion, and thumbprint computation for DPoP
token binding as specified in RFC 9449.
"""

from fiat_extension_x402.dpop.key_generation import (
    DPoPAlgorithm,
    DPoPKeyPair,
    compute_jwk_thumbprint,
    generate_dpop_keypair,
    to_dpop_jwk,
)
from fiat_extension_x402.dpop.proof_creation import create_dpop_proof
from fiat_extension_x402.dpop.proof_verification import (
    extract_dpop_thumbprint,
    verify_dpop_proof,
)
from fiat_extension_x402.dpop.types import (
    DPoPNonceStore,
    DPoPProofOptions,
    DPoPProofPayload,
    DPoPVerificationOptions,
)

__all__ = [
    "DPoPAlgorithm",
    "DPoPKeyPair",
    "DPoPNonceStore",
    "DPoPProofOptions",
    "DPoPProofPayload",
    "DPoPVerificationOptions",
    "compute_jwk_thumbprint",
    "create_dpop_proof",
    "extract_dpop_thumbprint",
    "generate_dpop_keypair",
    "to_dpop_jwk",
    "verify_dpop_proof",
]
