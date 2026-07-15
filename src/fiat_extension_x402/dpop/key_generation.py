# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""DPoP key generation, JWK conversion, and thumbprint computation.

Generate ephemeral key pairs for DPoP proof-of-possession, convert public keys
to the JWK format expected by Agent Pay, and compute RFC 7638 JWK thumbprints.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Literal, Union

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurve,
    EllipticCurvePrivateKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    generate_private_key as generate_rsa_private_key,
)

from fiat_extension_x402.exceptions import DPoPError
from fiat_extension_x402.schemas import DpopJwk

# Supported DPoP algorithms. For Agent Pay integration use EC algorithms (ES256,
# ES384, ES512). RS256 is supported for backward compatibility but not recommended
# for DPoP — Agent Pay only accepts EC keys for DPoP binding.
DPoPAlgorithm = Literal["ES256", "ES384", "ES512", "RS256"]

# Maps an EC algorithm to (curve instance, crv string, coordinate byte length).
_EC_ALGORITHM_PARAMS: dict[str, tuple[EllipticCurve, str, int]] = {
    "ES256": (SECP256R1(), "P-256", 32),
    "ES384": (SECP384R1(), "P-384", 48),
    "ES512": (SECP521R1(), "P-521", 66),
}

# RSA modulus length for RS256 key generation.
_RSA_MODULUS_LENGTH = 2048


def _base64url_encode(data: bytes) -> str:
    """Base64url-encode bytes without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_to_base64url(value: int) -> str:
    """Encode a non-negative integer as base64url (minimal big-endian bytes)."""
    length = (value.bit_length() + 7) // 8 or 1
    return _base64url_encode(value.to_bytes(length, byteorder="big"))


@dataclass(frozen=True)
class DPoPKeyPair:
    """DPoP key pair (ephemeral keys for proof-of-possession).

    :param private_key: Private key for signing (EC or RSA).
    :param public_jwk: Public key in JWK dict format.
    """

    private_key: Union[EllipticCurvePrivateKey, RSAPrivateKey]
    public_jwk: dict[str, str]


def generate_dpop_keypair(algorithm: DPoPAlgorithm = "ES256") -> DPoPKeyPair:
    """Generate a DPoP key pair.

    For Agent Pay integration, use EC algorithms (ES256, ES384, ES512). RS256 is
    supported for backward compatibility but not recommended for DPoP.

    :param algorithm: Algorithm to use (ES256 for P-256, ES384 for P-384,
        ES512 for P-521, RS256 for RSA).
    :returns: Key pair with private key and public JWK.
    :raises DPoPError: if the algorithm is unsupported or generation fails.
    """
    try:
        ec_params = _EC_ALGORITHM_PARAMS.get(algorithm)
        if ec_params is not None:
            curve, crv, coord_length = ec_params
            ec_private_key = generate_private_key(curve)
            public_numbers = ec_private_key.public_key().public_numbers()
            public_jwk: dict[str, str] = {
                "kty": "EC",
                "crv": crv,
                "x": _base64url_encode(public_numbers.x.to_bytes(coord_length, byteorder="big")),
                "y": _base64url_encode(public_numbers.y.to_bytes(coord_length, byteorder="big")),
                "alg": algorithm,
                "use": "sig",
            }
            return DPoPKeyPair(private_key=ec_private_key, public_jwk=public_jwk)

        if algorithm == "RS256":
            rsa_private_key = generate_rsa_private_key(
                public_exponent=65537,
                key_size=_RSA_MODULUS_LENGTH,
            )
            rsa_numbers = rsa_private_key.public_key().public_numbers()
            public_jwk = {
                "kty": "RSA",
                "n": _int_to_base64url(rsa_numbers.n),
                "e": _int_to_base64url(rsa_numbers.e),
                "alg": "RS256",
                "use": "sig",
            }
            return DPoPKeyPair(private_key=rsa_private_key, public_jwk=public_jwk)

        raise DPoPError(f"Unsupported algorithm: {algorithm}", {"algorithm": algorithm})
    except DPoPError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize unexpected failures
        raise DPoPError("Failed to generate DPoP key pair", {"error": str(exc)}) from exc


def to_dpop_jwk(keypair: DPoPKeyPair) -> DpopJwk:
    """Convert a DPoP key pair's public key to the DpopJwk format expected by Agent Pay.

    Agent Pay only accepts EC keys (P-256, P-384, P-521) with ``kty``, ``crv``, ``x``,
    ``y`` fields.

    :param keypair: DPoP key pair from :func:`generate_dpop_keypair`.
    :returns: A validated :class:`DpopJwk` suitable for ``CreateAgentPayment`` requests.
    :raises DPoPError: if the key is not a valid EC key.
    """
    jwk = keypair.public_jwk
    if jwk.get("kty") != "EC":
        raise DPoPError(
            "Agent Pay only supports EC keys for DPoP binding. Use ES256, ES384, or ES512.",
            {"kty": jwk.get("kty")},
        )
    crv = jwk.get("crv")
    x = jwk.get("x")
    y = jwk.get("y")
    if not crv or not x or not y:
        raise DPoPError("Invalid EC key: missing crv, x, or y", {"jwk": jwk})

    return DpopJwk(kty="EC", crv=crv, x=x, y=y)  # type: ignore[arg-type]


def compute_jwk_thumbprint(jwk: DpopJwk) -> str:
    """Compute the JWK thumbprint per RFC 7638 (SHA-256, base64url no-pad).

    Constructs the canonical JSON representation using only the required members
    for the key type (``crv``, ``kty``, ``x``, ``y`` for EC), lexicographically
    sorted, with no whitespace, then computes SHA-256 and returns the base64url
    encoding without padding.

    :param jwk: EC public key in :class:`DpopJwk` format.
    :returns: Base64url-encoded (no padding) SHA-256 thumbprint.
    :raises DPoPError: if thumbprint computation fails.
    """
    try:
        # RFC 7638 Section 3.2: for EC keys, the required members are crv, kty, x, y
        # in lexicographic order.
        canonical = json.dumps(
            {"crv": jwk.crv, "kty": jwk.kty, "x": jwk.x, "y": jwk.y},
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = hashlib.sha256(canonical.encode("utf-8")).digest()
        return _base64url_encode(digest)
    except Exception as exc:  # noqa: BLE001 - normalize unexpected failures
        raise DPoPError("Failed to compute JWK thumbprint", {"error": str(exc)}) from exc


__all__ = [
    "DPoPAlgorithm",
    "DPoPKeyPair",
    "compute_jwk_thumbprint",
    "generate_dpop_keypair",
    "to_dpop_jwk",
]
