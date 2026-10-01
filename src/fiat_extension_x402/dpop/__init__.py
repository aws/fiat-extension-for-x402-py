# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""DPoP (RFC 9449) proof verification."""

from __future__ import annotations

from fiat_extension_x402.dpop.types import (
    DPoPNonceStore,
    DPoPProofPayload,
    DPoPVerificationOptions,
)
from fiat_extension_x402.dpop.verification import (
    compute_jwk_thumbprint,
    extract_dpop_thumbprint,
    verify_dpop_proof,
)

__all__ = [
    "DPoPNonceStore",
    "DPoPProofPayload",
    "DPoPVerificationOptions",
    "compute_jwk_thumbprint",
    "extract_dpop_thumbprint",
    "verify_dpop_proof",
]
