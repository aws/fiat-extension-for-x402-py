# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""DPoP proof JWT verification per RFC 9449."""

from __future__ import annotations

import hashlib
import json
import math
import time
from base64 import urlsafe_b64encode
from typing import Any

import jwt as pyjwt

from fiat_extension_x402.exceptions import DPoPError

# Default maximum age (seconds) for DPoP proofs.
_DEFAULT_MAX_AGE = 60

# Clock skew tolerance (seconds).
_CLOCK_SKEW = 5

# DPoP proofs must be signed with an asymmetric key (RFC 9449 section 4.2).
_ALLOWED_DPOP_ALGORITHMS = frozenset({"ES256", "ES384", "ES512", "RS256", "PS256"})


def _base64url_encode_no_pad(data: bytes) -> str:
    """Base64url-encode without padding."""
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _replay_expires_at(iat: int, max_age: float) -> int:
    """Return the time from which a nonce store may forget a proof issued at ``iat``.

    The proof is accepted until ``now - iat`` exceeds ``max_age`` + clock skew,
    with ``now`` in whole seconds, so it must stay recorded until the second after
    that.
    """
    return iat + math.floor(max_age + _CLOCK_SKEW) + 1


def verify_dpop_proof(proof: str, options: dict[str, Any]) -> dict[str, Any]:
    """Verify a DPoP proof JWT and return its claims.

    Verification steps:

    1. Decode header and check ``typ`` is ``dpop+jwt``.
    2. Extract ``jwk`` from header and verify signature.
    3. Check freshness (``iat`` within ``max_age`` + clock skew).
    4. Verify HTTP method (``htm``) and URL (``htu``) binding.
    5. Verify ``ath`` (access token hash) if ``access_token`` is provided.
    6. Check replay via ``nonce_store`` if provided.

    :param proof: DPoP proof JWT string.
    :param options: Verification options.
    :returns: Decoded claims dict.
    :raises DPoPError: if verification fails.
    """
    try:
        unverified_header = pyjwt.get_unverified_header(proof)
    except Exception as exc:
        raise DPoPError("Invalid DPoP proof: cannot decode header", {"error": str(exc)}) from exc

    # 1. Check typ
    typ = unverified_header.get("typ", "")
    if typ.lower() != "dpop+jwt":
        raise DPoPError(f"Invalid DPoP proof type: expected 'dpop+jwt', got '{typ}'")

    # 2. Extract JWK and verify signature
    jwk_data = unverified_header.get("jwk")
    if not jwk_data:
        raise DPoPError("DPoP proof header missing 'jwk'")

    alg = unverified_header.get("alg")
    if not alg:
        raise DPoPError("DPoP proof header missing 'alg'")
    if alg not in _ALLOWED_DPOP_ALGORITHMS:
        raise DPoPError(f"DPoP proof algorithm not allowed: {alg}")

    try:
        key = pyjwt.PyJWK.from_dict({**jwk_data, "alg": alg}).key
    except pyjwt.PyJWTError:
        # PyJWT's key-import errors can include the whole JWK, so name it by kid.
        kid = jwk_data.get("kid")
        label = f"JWK {kid}" if isinstance(kid, str) else "JWK"
        raise DPoPError(
            f"DPoP proof signature verification failed: {label}: invalid key material"
        ) from None
    try:
        claims: dict[str, Any] = pyjwt.decode(
            proof,
            key,
            algorithms=[alg],
            # Disable PyJWT's own iat/exp checks so the clock-skew-tolerant
            # freshness check below is authoritative.
            options={"verify_exp": False, "verify_aud": False, "verify_iat": False},
        )
    except pyjwt.PyJWTError as exc:
        raise DPoPError(f"DPoP proof signature verification failed: {exc}") from exc

    # Validate required claims are present.
    if not all(claims.get(claim) for claim in ("jti", "htm", "htu", "iat")):
        raise DPoPError("Missing required DPoP claims")

    # 3. Check freshness
    max_age = options.get("max_age", _DEFAULT_MAX_AGE)
    # ``iat`` is present: the required-claims check above rejects proofs without it.
    iat = int(claims["iat"])
    now = int(time.time())
    if iat > now + _CLOCK_SKEW:
        raise DPoPError("DPoP proof issued in the future")
    if now - iat > max_age + _CLOCK_SKEW:
        raise DPoPError("DPoP proof expired")

    # 4. Verify HTTP method and URL binding
    expected_htm = options.get("htm")
    if expected_htm and claims.get("htm") != expected_htm:
        raise DPoPError(
            f"DPoP proof htm mismatch: expected '{expected_htm}', got '{claims.get('htm')}'"
        )

    expected_htu = options.get("htu")
    if expected_htu and claims.get("htu") != expected_htu:
        raise DPoPError(
            f"DPoP proof htu mismatch: expected '{expected_htu}', got '{claims.get('htu')}'"
        )

    # 5. Verify access token hash
    access_token = options.get("access_token")
    if access_token:
        expected_ath = _base64url_encode_no_pad(
            hashlib.sha256(access_token.encode("ascii")).digest()
        )
        actual_ath = claims.get("ath")
        if actual_ath != expected_ath:
            raise DPoPError("DPoP proof access token hash (ath) mismatch")

    # 6. Replay prevention via nonce store, keyed on the unique proof id (jti).
    nonce_store = options.get("nonce_store")
    if nonce_store is not None:
        jti = claims["jti"]
        if nonce_store.has(jti):
            raise DPoPError("DPoP proof replay detected", {"jti": jti})
        nonce_store.add(jti, _replay_expires_at(iat, max_age))

    return claims


def extract_dpop_thumbprint(proof: str) -> str:
    """Extract the JWK thumbprint (jkt) from a DPoP proof JWT.

    Computes the RFC 7638 SHA-256 thumbprint of the public key embedded in
    the proof header.

    :param proof: DPoP proof JWT string.
    :returns: Base64url-encoded (no padding) SHA-256 thumbprint.
    :raises DPoPError: if extraction fails.
    """
    try:
        unverified_header = pyjwt.get_unverified_header(proof)
    except Exception as exc:
        raise DPoPError(
            "Cannot extract thumbprint: invalid DPoP proof", {"error": str(exc)}
        ) from exc

    jwk_data = unverified_header.get("jwk")
    if not jwk_data:
        raise DPoPError("DPoP proof header missing 'jwk'")

    return compute_jwk_thumbprint(jwk_data)


def compute_jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """Compute the RFC 7638 SHA-256 thumbprint of a public JWK.

    :param jwk: Public key as a JWK (``EC`` or ``RSA``).
    :returns: Base64url-encoded (no padding) SHA-256 thumbprint.
    :raises DPoPError: if the key type is unsupported.
    """
    kty = jwk.get("kty", "")
    required: tuple[str, ...]
    if kty == "EC":
        required = ("crv", "kty", "x", "y")
    elif kty == "RSA":
        required = ("e", "kty", "n")
    else:
        raise DPoPError(f"Unsupported key type in DPoP proof: {kty}")

    canonical_obj = {k: jwk[k] for k in sorted(required) if k in jwk}
    canonical = json.dumps(canonical_obj, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return _base64url_encode_no_pad(digest)


__all__ = ["compute_jwk_thumbprint", "extract_dpop_thumbprint", "verify_dpop_proof"]
