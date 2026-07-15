# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Local (in-process) signers for development and testing.

These signers hold a private key in memory and sign JWTs directly using PyJWT.
They are NOT suitable for production use where keys should be managed by KMS.
"""

from __future__ import annotations

from typing import Any, Union

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from fiat_extension_x402.exceptions import ValidationError


class _LocalServiceSigner:
    """In-process signer implementing the ServiceAgentPaySigner protocol."""

    def __init__(
        self,
        private_key: Union[EllipticCurvePrivateKey, RSAPrivateKey],
        public_jwk: dict[str, str],
        service_url: str,
    ) -> None:
        self._private_key = private_key
        self._public_jwk = public_jwk
        self._service_url = service_url
        self._algorithm = public_jwk.get("alg", "ES256")

    async def sign_quote(self, payload: dict[str, Any]) -> str:
        """Sign a quote token payload and return the compact JWT string."""
        token: str = pyjwt.encode(
            payload,
            self._private_key,
            algorithm=self._algorithm,
            headers={"kid": self._public_jwk.get("kid", "local-dev-key")},
        )
        return token

    def get_public_key(self) -> object:
        """Return the public JWK dict."""
        return self._public_jwk

    def get_service_url(self) -> str:
        """Return the service URL (issuer)."""
        return self._service_url


class _LocalAgentPaySigner:
    """In-process signer for buyer-side operations (payment token binding)."""

    def __init__(
        self,
        private_key: Union[EllipticCurvePrivateKey, RSAPrivateKey],
        public_jwk: dict[str, str],
        agent_pay_id: str,
    ) -> None:
        self._private_key = private_key
        self._public_jwk = public_jwk
        self._agent_pay_id = agent_pay_id
        self._algorithm = public_jwk.get("alg", "ES256")

    async def sign(self, payload: dict[str, Any]) -> str:
        """Sign a payload and return the compact JWT string."""
        token: str = pyjwt.encode(
            payload,
            self._private_key,
            algorithm=self._algorithm,
        )
        return token

    def get_public_key(self) -> object:
        """Return the public JWK dict."""
        return self._public_jwk

    def get_agent_pay_id(self) -> str:
        """Return the agent pay identifier."""
        return self._agent_pay_id


def to_service_agent_pay_signer(
    private_key: Union[EllipticCurvePrivateKey, RSAPrivateKey],
    public_jwk: dict[str, str],
    service_url: str,
) -> _LocalServiceSigner:
    """Create a local (in-process) service signer for development/testing.

    :param private_key: EC or RSA private key for signing.
    :param public_jwk: Public key in JWK dict format.
    :param service_url: Service URL used as the ``iss`` claim.
    :returns: A signer implementing the :class:`ServiceAgentPaySigner` protocol.
    :raises ValidationError: if ``service_url`` is empty.
    """
    if not service_url or not service_url.strip():
        raise ValidationError(
            "service_url is required and must be non-empty. It becomes the quote "
            "token's 'iss' claim, which Agent Pay requires."
        )
    return _LocalServiceSigner(private_key, public_jwk, service_url)


def to_agent_pay_signer(
    private_key: Union[EllipticCurvePrivateKey, RSAPrivateKey],
    public_jwk: dict[str, str],
    agent_pay_id: str,
) -> _LocalAgentPaySigner:
    """Create a local (in-process) agent pay signer for development/testing.

    :param private_key: EC or RSA private key for signing.
    :param public_jwk: Public key in JWK dict format.
    :param agent_pay_id: Agent Pay identifier for the signer.
    :returns: A local agent pay signer.
    """
    return _LocalAgentPaySigner(private_key, public_jwk, agent_pay_id)


__all__ = [
    "to_agent_pay_signer",
    "to_service_agent_pay_signer",
]
