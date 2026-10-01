# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""In-process quote signer for development and testing.

Holds a private key in memory and signs JWTs directly with PyJWT. Not suitable
for production, where keys should be managed by KMS.
"""

from __future__ import annotations

from typing import Any, Union

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from fiat_extension_x402.exceptions import SigningError


class LocalQuoteSigner:
    """Quote signer holding its private key in memory.

    :param private_key: EC or RSA private key.
    :param public_jwk: Public key as a JWK. ``alg`` selects the signing algorithm
        (default ``ES256``) and ``kid`` becomes the JWS ``kid`` header.
    :param service_url: Service URL used as the ``iss`` claim.
    :raises SigningError: if ``service_url`` is empty.
    """

    def __init__(
        self,
        private_key: Union[EllipticCurvePrivateKey, RSAPrivateKey],
        public_jwk: dict[str, str],
        service_url: str,
    ) -> None:
        if not service_url or not service_url.strip():
            raise SigningError(
                "service_url is required and must be non-empty. It becomes the quote "
                "token's 'iss' claim, which the service requires."
            )
        self._private_key = private_key
        self._public_jwk = public_jwk
        self._service_url = service_url
        self._algorithm = public_jwk.get("alg", "ES256")

    @property
    def public_jwk(self) -> dict[str, str]:
        """The public key as a JWK, for publishing in the seller's JWKS."""
        return self._public_jwk

    def sign_quote(self, payload: dict[str, Any]) -> str:
        """Sign quote token claims and return the compact JWS."""
        headers = {"kid": self._public_jwk["kid"]} if "kid" in self._public_jwk else None
        token: str = pyjwt.encode(
            payload, self._private_key, algorithm=self._algorithm, headers=headers
        )
        return token

    def get_service_url(self) -> str:
        """Return the service URL (issuer)."""
        return self._service_url


__all__ = ["LocalQuoteSigner"]
