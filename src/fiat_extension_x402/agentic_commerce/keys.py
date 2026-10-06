# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Where the facilitator finds the seller's quote-signing public key."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Optional, Union

import jwt

from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.security import ALLOWED_ALGORITHMS
from fiat_extension_x402.signers.local import MIN_RSA_KEY_BITS, PRIVATE_JWK_MEMBERS

# JWS algorithm required for each supported EC curve.
_EC_CURVE_ALGORITHMS = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}


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
    :raises ValidationError: if no key is given, a ``kid`` is missing or
        repeats, or a key is not a valid public key that verifiers accept: EC on
        P-256/P-384/P-521 or RSA of at least 2048 bits, with an allowed ``alg``
        that matches the key and no private key material.
    """
    if not public_jwks:
        raise ValidationError("At least one public key is required")
    keys: list[dict[str, Any]] = []
    seen: set[str] = set()
    for jwk in public_jwks:
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid.strip():
            raise ValidationError("Every JWK needs a non-empty string 'kid'")
        if kid in seen:
            raise ValidationError(f"Duplicate kid: {kid}")
        _validate_public_jwk(jwk, kid)
        seen.add(kid)
        keys.append(dict(jwk))
    return {"keys": keys}


def _validate_public_jwk(jwk: Mapping[str, Any], kid: str) -> None:
    """Check a JWK is a public signing key that verifiers accept."""
    leaked = PRIVATE_JWK_MEMBERS & jwk.keys()
    if leaked:
        raise ValidationError(f"JWK {kid}: contains private key members {sorted(leaked)}")
    kty = jwk.get("kty")
    if kty == "EC":
        crv = jwk.get("crv")
        expected_alg = _EC_CURVE_ALGORITHMS.get(crv) if isinstance(crv, str) else None
        if expected_alg is None:
            raise ValidationError(f"JWK {kid}: unsupported EC curve {crv!r}")
    elif kty == "RSA":
        expected_alg = "RS256"
    else:
        raise ValidationError(f"JWK {kid}: kty must be 'EC' or 'RSA', got {kty!r}")
    alg = jwk.get("alg", expected_alg)
    if alg not in ALLOWED_ALGORITHMS or alg != expected_alg:
        raise ValidationError(f"JWK {kid}: alg {alg!r} does not match the key (use {expected_alg})")
    if jwk.get("use", "sig") != "sig":
        raise ValidationError(f"JWK {kid}: use must be 'sig', got {jwk.get('use')!r}")
    # Parses the key material: base64url values, coordinate sizes, and that an
    # EC point lies on its curve.
    try:
        key = jwt.PyJWK.from_dict(dict(jwk), algorithm=alg).key
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise ValidationError(f"JWK {kid}: invalid key material: {exc}") from exc
    if kty == "RSA" and key.key_size < MIN_RSA_KEY_BITS:
        raise ValidationError(
            f"JWK {kid}: RSA keys must be at least {MIN_RSA_KEY_BITS} bits, got {key.key_size}"
        )


__all__ = [
    "JwksSellerKeyResolver",
    "KmsSellerKeyResolver",
    "SellerKeyResolver",
    "StaticSellerKeyResolver",
    "jwks_document",
]
