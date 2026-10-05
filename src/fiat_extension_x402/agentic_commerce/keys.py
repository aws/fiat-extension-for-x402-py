# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Where the facilitator finds the seller's quote-signing public key."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Optional, Union


@dataclass(frozen=True)
class KmsSellerKeyResolver:
    """Resolve the seller's public key from KMS via ``kms:GetPublicKey``.

    :param kms_key_arn: ARN of the seller's signing key.
    :param region: Region hosting the key.
    :param credentials: Callable returning credentials for the KMS call. Omit to
        use the ambient boto3 credential chain.
    """

    kms_key_arn: str
    region: str
    credentials: Optional[Callable[[], Any]] = None
    # Allow injecting a pre-configured KMS client (useful for testing).
    kms_client: Any = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class JwksSellerKeyResolver:
    """Resolve the seller's public key from the seller's own JWKS.

    :param jwks_url: Base URL. ``/.well-known/jwks.json`` is appended.
    """

    jwks_url: str


@dataclass(frozen=True)
class StaticSellerKeyResolver:
    """Use a public key the seller already holds (for example, a local signer's).

    :param public_jwk: The seller's public key as a JWK.
    """

    public_jwk: dict[str, Any]


#: Strategy for locating the seller's quote-signing key. The key is always
#: configured by the seller, never discovered from the quote token itself.
SellerKeyResolver = Union[KmsSellerKeyResolver, JwksSellerKeyResolver, StaticSellerKeyResolver]

__all__ = [
    "JwksSellerKeyResolver",
    "KmsSellerKeyResolver",
    "SellerKeyResolver",
    "StaticSellerKeyResolver",
]
