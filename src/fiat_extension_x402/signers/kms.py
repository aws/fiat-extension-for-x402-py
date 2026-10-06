# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""AWS KMS signer for quote tokens.

Provides a production-ready :class:`~fiat_extension_x402.signers.QuoteSigner`
that signs quote tokens using an AWS KMS asymmetric key (ECC_NIST_P384 / ES384).
The private key never leaves KMS — signing happens server-side via the KMS
Sign API.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

import boto3  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from fiat_extension_x402.exceptions import SigningError

# Maps KMS algorithm to JWT ``alg`` header value.
_ALG_MAP: dict[str, str] = {
    "ECDSA_SHA_256": "ES256",
    "ECDSA_SHA_384": "ES384",
    "ECDSA_SHA_512": "ES512",
}

# Maps KMS algorithm to the fixed-width byte length of each r/s component.
_COMPONENT_LENGTH: dict[str, int] = {
    "ECDSA_SHA_256": 32,
    "ECDSA_SHA_384": 48,
    "ECDSA_SHA_512": 66,
}


def _base64url_encode(data: bytes) -> str:
    """Base64url-encode bytes without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _der_to_raw(der_signature: bytes, component_length: int) -> bytes:
    """Convert a DER-encoded ECDSA signature to fixed-width raw ``r||s`` format.

    KMS returns signatures in DER (ASN.1) format. JWTs require raw
    concatenation: ``r`` (fixed-length) || ``s`` (fixed-length).

    Uses ``cryptography``'s :func:`decode_dss_signature` to reliably parse the
    DER structure, then zero-pads each integer to the required width.
    """
    r, s = decode_dss_signature(der_signature)
    r_bytes = r.to_bytes(component_length, byteorder="big")
    s_bytes = s.to_bytes(component_length, byteorder="big")
    return r_bytes + s_bytes


@dataclass(frozen=True)
class KmsQuoteSignerConfig:
    """Configuration for :class:`KmsQuoteSigner`.

    :param key_arn: KMS key ARN or alias ARN.
    :param region: AWS region where the KMS key lives.
    :param service_url: Service URL used as the ``iss`` claim in quote tokens.
    :param algorithm: Signing algorithm. Defaults to ``ECDSA_SHA_384``.
    :param kid: Key ID for the JWT ``kid`` header. Derived from the ARN if omitted.
    """

    key_arn: str
    region: str
    service_url: str
    algorithm: str = "ECDSA_SHA_384"
    kid: str | None = None
    # Allow injecting a pre-configured KMS client (useful for testing).
    _kms_client: Any = field(default=None, repr=False, compare=False)


class KmsQuoteSigner:
    """Quote signer backed by an AWS KMS asymmetric EC key.

    The private key never leaves KMS: signing happens server-side via the KMS
    ``Sign`` API.

    :param config: Signer configuration.
    :raises SigningError: if the algorithm is not supported or ``service_url`` is empty.
    """

    def __init__(self, config: KmsQuoteSignerConfig) -> None:
        if not config.service_url or not config.service_url.strip():
            raise SigningError(
                "service_url is required and must be non-empty. It becomes the quote "
                "token's 'iss' claim, which the service requires."
            )
        if config.algorithm not in _ALG_MAP:
            raise SigningError(
                f"Unsupported algorithm: {config.algorithm}",
                {"supported": list(_ALG_MAP.keys())},
            )
        self._key_arn = config.key_arn
        self._service_url = config.service_url
        self._algorithm = config.algorithm
        self._jwt_alg = _ALG_MAP[config.algorithm]
        self._component_length = _COMPONENT_LENGTH[config.algorithm]

        # Derive kid from ARN if not explicitly provided.
        # e.g., 'arn:aws:kms:us-east-1:123:alias/my-key' -> 'my-key'
        # e.g., 'arn:aws:kms:us-east-1:123:key/abc-123'  -> 'key/abc-123'
        if config.kid is not None:
            self._kid = config.kid
        else:
            arn_last_segment = config.key_arn.rsplit(":", maxsplit=1)[-1]
            if arn_last_segment.startswith("alias/"):
                self._kid = arn_last_segment[len("alias/") :]
            else:
                self._kid = arn_last_segment

        if config._kms_client is not None:
            self._kms_client = config._kms_client
        else:
            self._kms_client = boto3.client("kms", region_name=config.region)

    def sign_quote(self, payload: dict[str, Any]) -> str:
        """Sign a quote token payload via KMS and return the compact JWT.

        Constructs the JWS header and payload segments, signs via the KMS
        ``Sign`` API, converts the DER signature to raw ``r||s``, and
        returns the compact serialization.
        """
        header = _base64url_encode(
            json.dumps(
                {"alg": self._jwt_alg, "typ": "JWT", "kid": self._kid},
                separators=(",", ":"),
            ).encode()
        )
        body = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        message = f"{header}.{body}".encode()

        try:
            response = self._kms_client.sign(
                KeyId=self._key_arn,
                Message=message,
                MessageType="RAW",
                SigningAlgorithm=self._algorithm,
            )
        except Exception as exc:
            raise SigningError(f"KMS Sign API call failed: {exc}") from exc

        der_signature: bytes = response["Signature"]
        if not der_signature:
            raise SigningError("KMS Sign returned no signature")

        raw_signature = _der_to_raw(der_signature, self._component_length)
        signature = _base64url_encode(raw_signature)

        return f"{header}.{body}.{signature}"

    def get_service_url(self) -> str:
        """Return the service URL (issuer)."""
        return self._service_url


__all__ = [
    "KmsQuoteSigner",
    "KmsQuoteSignerConfig",
]
