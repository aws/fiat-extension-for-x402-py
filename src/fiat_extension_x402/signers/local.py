# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Quote signer for a private key the seller manages.

Holds the private key in memory and signs JWTs directly with PyJWT. Use it with
a key loaded from the seller's own store (a PEM file, a secrets manager, an
HSM export) and publish the public key in a JWKS; see
:func:`~fiat_extension_x402.agentic_commerce.keys.jwks_document`. Sellers who
prefer the private key never to leave AWS use
:class:`~fiat_extension_x402.signers.KmsQuoteSigner` instead.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from fiat_extension_x402.exceptions import SigningError

# JWK members that only private keys carry (RFC 7518 §6).
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

# JWS algorithm for each supported EC curve.
_EC_ALGORITHMS = {"secp256r1": "ES256", "secp384r1": "ES384", "secp521r1": "ES512"}

# Smallest RSA modulus accepted for quote signing (NIST SP 800-57: 2048 bits).
MIN_RSA_KEY_BITS = 2048

# An unencrypted PKCS #8 PEM block, the only PEM form whose key algorithm is readable.
_PKCS8_PEM = re.compile(rb"-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----", re.DOTALL)

# id-RSASSA-PSS (1.2.840.113549.1.1.10), the DER contents of the OID.
_RSA_PSS_OID = bytes.fromhex("2a864886f70d01010a")


def _der_header(der: bytes, offset: int, tag: int) -> tuple[int, int]:
    """Return the content offset and length of the DER element at ``offset``.

    :raises ValueError: if the element does not have ``tag`` or a supported length.
    :raises IndexError: if ``der`` ends early.
    """
    if der[offset] != tag:
        raise ValueError("unexpected DER tag")
    first = der[offset + 1]
    if first < 0x80:
        return offset + 2, first
    count = first & 0x7F
    if not 1 <= count <= 4:
        raise ValueError("unsupported DER length")
    start = offset + 2 + count
    return start, int.from_bytes(der[offset + 2 : start], "big")


def _is_rsa_pss_key(pem: bytes) -> bool:
    """Whether ``pem`` is an unencrypted PKCS #8 key marked RSA-PSS only.

    ``cryptography`` loads such a key as an ordinary RSA key and drops the
    marking, so it is read from the PEM before loading: the algorithm OID of the
    PrivateKeyInfo (RFC 5208). Anything that does not parse is left to the PEM
    loader to report.
    """
    match = _PKCS8_PEM.search(pem)
    if match is None:
        return False
    try:
        der = base64.b64decode(b"".join(match.group(1).split()), validate=True)
        info, _ = _der_header(der, 0, 0x30)  # PrivateKeyInfo
        version, length = _der_header(der, info, 0x02)
        algorithm, _ = _der_header(der, version + length, 0x30)  # AlgorithmIdentifier
        oid, length = _der_header(der, algorithm, 0x06)
    except (ValueError, IndexError):  # binascii.Error is a ValueError
        return False
    return der[oid : oid + length] == _RSA_PSS_OID


class LocalQuoteSigner:
    """Quote signer holding its private key in memory.

    :param private_key: EC or RSA private key.
    :param public_jwk: Public key as a JWK. ``alg`` selects the signing algorithm
        (default ``ES256``) and ``kid`` becomes the JWS ``kid`` header.
    :param service_url: Service URL used as the ``iss`` claim.
    :raises SigningError: if ``service_url`` is empty, ``public_jwk`` contains
        private key material, or an RSA key is shorter than 2048 bits.
    """

    def __init__(
        self,
        private_key: EllipticCurvePrivateKey | RSAPrivateKey,
        public_jwk: dict[str, str],
        service_url: str,
    ) -> None:
        if not service_url or not service_url.strip():
            raise SigningError(
                "service_url is required and must be non-empty. It becomes the quote "
                "token's 'iss' claim, which the service requires."
            )
        leaked = PRIVATE_JWK_MEMBERS & public_jwk.keys()
        if leaked:
            raise SigningError(
                f"public_jwk contains private key members: {sorted(leaked)}. "
                "Pass only the public key."
            )
        if isinstance(private_key, RSAPrivateKey) and private_key.key_size < MIN_RSA_KEY_BITS:
            raise SigningError(
                f"RSA keys must be at least {MIN_RSA_KEY_BITS} bits, got {private_key.key_size}"
            )
        self._private_key = private_key
        self._public_jwk = public_jwk
        self._service_url = service_url
        self._algorithm = public_jwk.get("alg", "ES256")

    @classmethod
    def from_pem(
        cls,
        pem: str | bytes,
        *,
        kid: str,
        service_url: str,
        password: bytes | None = None,
    ) -> LocalQuoteSigner:
        """Create a signer from a PEM-encoded private key.

        The public JWK is derived from the key. The algorithm follows the key:
        ``ES256``/``ES384``/``ES512`` for P-256/P-384/P-521 and ``RS256`` for RSA.

        RSA keys marked for RSA-PSS only (for example from ``openssl genpkey
        -algorithm RSA-PSS``) are rejected, because quote tokens are signed with
        RS256 (PKCS #1 v1.5), which such a key does not allow. The marking can
        only be read from an unencrypted PEM; an encrypted RSA-PSS PEM loads as a
        plain RSA key.

        :param pem: The PEM-encoded private key.
        :param kid: Key ID published in the JWKS and sent as the JWS ``kid``.
        :param service_url: Service URL used as the ``iss`` claim.
        :param password: Password for an encrypted PEM.
        :raises SigningError: if the key cannot be loaded, is not EC (P-256,
            P-384, P-521) or RSA of at least 2048 bits, is marked RSA-PSS only,
            or ``kid`` is empty.
        """
        if not kid or not kid.strip():
            raise SigningError("kid is required and must be non-empty.")
        data = pem.encode() if isinstance(pem, str) else pem
        if _is_rsa_pss_key(data):
            raise SigningError("Only EC and RSA private keys are supported.")
        try:
            private_key = load_pem_private_key(data, password=password)
        except (TypeError, ValueError) as exc:
            raise SigningError(f"Could not load the PEM private key: {exc}") from exc

        if isinstance(private_key, EllipticCurvePrivateKey):
            alg = _EC_ALGORITHMS.get(private_key.curve.name)
            if alg is None:
                raise SigningError(f"Unsupported EC curve: {private_key.curve.name}")
            jwk = pyjwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key())
        elif isinstance(private_key, RSAPrivateKey):
            alg = "RS256"
            jwk = pyjwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key())
        else:
            raise SigningError("Only EC and RSA private keys are supported.")

        public_jwk: dict[str, str] = json.loads(jwk)
        public_jwk.update(alg=alg, kid=kid, use="sig")
        return cls(private_key, public_jwk, service_url)

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
