# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""DPoP proof JWT creation per RFC 9449."""

from __future__ import annotations

import hashlib
import time
import uuid
from base64 import urlsafe_b64encode
from typing import Any

import jwt as pyjwt

from fiat_extension_x402.dpop.key_generation import DPoPKeyPair
from fiat_extension_x402.exceptions import DPoPError


def create_dpop_proof(keypair: DPoPKeyPair, options: dict[str, Any]) -> str:
    """Create a DPoP proof JWT signed by the given key pair.

    The proof binds an HTTP request (method + URL) to the key pair. An optional
    ``access_token`` triggers inclusion of the ``ath`` (access token hash) claim.

    :param keypair: DPoP key pair for signing.
    :param options: Proof options specifying HTTP method, URL, and optional token/nonce.
    :returns: Compact JWS DPoP proof.
    :raises DPoPError: if proof creation fails.
    """
    try:
        jwk = keypair.public_jwk
        alg = jwk.get("alg", "ES256")

        htm = options.get("htm", "")
        htu = options.get("htu", "")
        if not htm:
            raise DPoPError("DPoP proof requires an HTTP method (htm)")
        if not htu:
            raise DPoPError("DPoP proof requires an HTTP URL (htu)")

        payload: dict[str, Any] = {
            "jti": str(uuid.uuid4()),
            "htm": htm.upper(),
            "htu": htu,
            "iat": int(time.time()),
        }

        access_token = options.get("access_token")
        if access_token:
            digest = hashlib.sha256(access_token.encode("ascii")).digest()
            payload["ath"] = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        nonce = options.get("nonce")
        if nonce:
            payload["nonce"] = nonce

        headers: dict[str, Any] = {
            "typ": "dpop+jwt",
            "alg": alg,
            "jwk": jwk,
        }

        token: str = pyjwt.encode(
            payload,
            keypair.private_key,
            algorithm=alg,
            headers=headers,
        )
        return token
    except DPoPError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize unexpected failures
        raise DPoPError("Failed to create DPoP proof", {"error": str(exc)}) from exc


__all__ = ["create_dpop_proof"]
