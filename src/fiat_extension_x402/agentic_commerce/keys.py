# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Where the facilitator finds the seller's quote-signing public key."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Optional, Union

from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.signers.local import PRIVATE_JWK_MEMBERS


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


def jwks_document(*public_jwks: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Build the JWKS a seller serves at ``/.well-known/jwks.json``.

    Pass the current key and, during a rotation, the previous one, so quotes
    signed with either still verify. Each key needs a unique ``kid``: verifiers
    select the key by the ``kid`` in the quote token's header.

    :param public_jwks: Public keys as JWKs, for example
        :attr:`LocalQuoteSigner.public_jwk
        <fiat_extension_x402.signers.LocalQuoteSigner.public_jwk>`.
    :returns: ``{"keys": [...]}``, ready to serialize as JSON.
    :raises ValidationError: if no key is given, a key lacks ``kty`` or ``kid``,
        a ``kid`` repeats, or a key contains private key material.
    """
    if not public_jwks:
        raise ValidationError("At least one public key is required")
    keys: list[dict[str, Any]] = []
    seen: set[str] = set()
    for jwk in public_jwks:
        leaked = PRIVATE_JWK_MEMBERS & jwk.keys()
        if leaked:
            raise ValidationError(f"JWK contains private key members: {sorted(leaked)}")
        kid = jwk.get("kid")
        if not jwk.get("kty") or not kid:
            raise ValidationError("Every JWK needs 'kty' and 'kid'")
        if kid in seen:
            raise ValidationError(f"Duplicate kid: {kid}")
        seen.add(kid)
        keys.append(dict(jwk))
    return {"keys": keys}


__all__ = [
    "JwksSellerKeyResolver",
    "KmsSellerKeyResolver",
    "SellerKeyResolver",
    "StaticSellerKeyResolver",
    "jwks_document",
]
