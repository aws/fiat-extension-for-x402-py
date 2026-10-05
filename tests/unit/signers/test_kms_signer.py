# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the KMS signer module."""

from __future__ import annotations

import base64
import json

import boto3  # type: ignore[import-untyped]
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from moto import mock_aws

from fiat_extension_x402.exceptions import SigningError
from fiat_extension_x402.signers.kms import (
    KmsQuoteSigner,
    KmsQuoteSignerConfig,
    _base64url_encode,
    _der_to_raw,
)
from fiat_extension_x402.signers.protocol import QuoteSigner


def _base64url_decode(s: str) -> bytes:
    """Decode base64url string with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


class TestKmsQuoteSignerInit:
    """Tests for KmsQuoteSigner construction."""

    def test_unsupported_algorithm_raises_signing_error(self) -> None:
        config = KmsQuoteSignerConfig(
            key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
            region="us-east-1",
            service_url="https://api.example.com",
            algorithm="INVALID_ALGO",
        )
        with pytest.raises(SigningError, match="Unsupported algorithm"):
            KmsQuoteSigner(config)

    def test_empty_service_url_raises_signing_error(self) -> None:
        config = KmsQuoteSignerConfig(
            key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
            region="us-east-1",
            service_url="",
        )
        with pytest.raises(SigningError, match="service_url is required"):
            KmsQuoteSigner(config)

    def test_whitespace_service_url_raises_signing_error(self) -> None:
        config = KmsQuoteSignerConfig(
            key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
            region="us-east-1",
            service_url="   ",
        )
        with pytest.raises(SigningError, match="service_url is required"):
            KmsQuoteSigner(config)

    @mock_aws
    def test_creates_signer_satisfying_protocol(self) -> None:
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
        key_arn = key["KeyMetadata"]["Arn"]

        config = KmsQuoteSignerConfig(
            key_arn=key_arn,
            region="us-east-1",
            service_url="https://api.example.com",
            _kms_client=client,
        )
        signer = KmsQuoteSigner(config)
        assert isinstance(signer, QuoteSigner)

    @mock_aws
    def test_default_algorithm_is_ecdsa_sha_384(self) -> None:
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
        key_arn = key["KeyMetadata"]["Arn"]

        config = KmsQuoteSignerConfig(
            key_arn=key_arn,
            region="us-east-1",
            service_url="https://api.example.com",
            _kms_client=client,
        )
        signer = KmsQuoteSigner(config)
        assert signer._jwt_alg == "ES384"

    @mock_aws
    def test_builds_default_kms_client_when_not_injected(self) -> None:
        # No _kms_client provided -> the signer constructs its own boto3 client.
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
        key_arn = key["KeyMetadata"]["Arn"]

        config = KmsQuoteSignerConfig(
            key_arn=key_arn,
            region="us-east-1",
            service_url="https://api.example.com",
        )
        signer = KmsQuoteSigner(config)
        assert signer._kms_client is not None


class TestKmsSignerKidDerivation:
    """Tests for kid derivation from ARN."""

    @mock_aws
    def test_kid_from_alias_arn(self) -> None:
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
        key_id = key["KeyMetadata"]["KeyId"]
        client.create_alias(AliasName="alias/my-quote-key", TargetKeyId=key_id)

        config = KmsQuoteSignerConfig(
            key_arn="arn:aws:kms:us-east-1:123456789012:alias/my-quote-key",
            region="us-east-1",
            service_url="https://api.example.com",
            _kms_client=client,
        )
        signer = KmsQuoteSigner(config)
        assert signer._kid == "my-quote-key"

    @mock_aws
    def test_kid_from_key_arn(self) -> None:
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
        key_arn = key["KeyMetadata"]["Arn"]

        config = KmsQuoteSignerConfig(
            key_arn=key_arn,
            region="us-east-1",
            service_url="https://api.example.com",
            _kms_client=client,
        )
        signer = KmsQuoteSigner(config)
        # ARN ends with "key/<uuid>" so kid should be "key/<uuid>"
        assert signer._kid.startswith("key/")

    @mock_aws
    def test_explicit_kid_overrides_derivation(self) -> None:
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
        key_arn = key["KeyMetadata"]["Arn"]

        config = KmsQuoteSignerConfig(
            key_arn=key_arn,
            region="us-east-1",
            service_url="https://api.example.com",
            kid="custom-kid",
            _kms_client=client,
        )
        signer = KmsQuoteSigner(config)
        assert signer._kid == "custom-kid"


class TestKmsSignerSignQuote:
    """Tests for the sign_quote method."""

    def test_produces_valid_jwt_structure(self) -> None:
        with mock_aws():
            client = boto3.client("kms", region_name="us-east-1")
            key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
            key_arn = key["KeyMetadata"]["Arn"]

            config = KmsQuoteSignerConfig(
                key_arn=key_arn,
                region="us-east-1",
                service_url="https://api.example.com",
                _kms_client=client,
            )
            signer = KmsQuoteSigner(config)

            payload: dict[str, object] = {
                "iss": "https://api.example.com",
                "aud": "aws:marketplace",
                "iat": 1700000000,
                "exp": 1700000300,
                "jti": "test-jti-123",
                "price": {"amount": "0.15", "currency": "USD"},
                "payTo": "seller-id-123",
                "reference": "RESOURCE",
            }

            token = signer.sign_quote(payload)

            # JWT has three parts.
            parts = token.split(".")
            assert len(parts) == 3

            # Decode header.
            header = json.loads(_base64url_decode(parts[0]))
            assert header["alg"] == "ES384"
            assert header["typ"] == "JWT"
            assert "kid" in header

            # Decode payload.
            decoded_payload = json.loads(_base64url_decode(parts[1]))
            assert decoded_payload["iss"] == "https://api.example.com"
            assert decoded_payload["aud"] == "aws:marketplace"
            assert decoded_payload["jti"] == "test-jti-123"

    def test_signature_is_verifiable(self) -> None:
        """Sign JWTs, then verify each signature using the KMS public key.

        This proves the DER-to-raw conversion produces a correct JWS signature.
        ECDSA r/s values vary per signature, and a fixed-width padding bug only
        surfaces when r or s needs a leading zero byte (~1% of signatures), so
        this signs many tokens to catch such a bug statistically.
        """
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        with mock_aws():
            client = boto3.client("kms", region_name="us-east-1")
            key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
            key_arn = key["KeyMetadata"]["Arn"]
            key_id = key["KeyMetadata"]["KeyId"]

            # Get public key for verification.
            pub_resp = client.get_public_key(KeyId=key_id)
            public_key = load_der_public_key(pub_resp["PublicKey"])
            assert isinstance(public_key, ec.EllipticCurvePublicKey)

            config = KmsQuoteSignerConfig(
                key_arn=key_arn,
                region="us-east-1",
                service_url="https://api.example.com",
                _kms_client=client,
            )
            signer = KmsQuoteSigner(config)

            for i in range(50):
                payload: dict[str, object] = {
                    "iss": "https://api.example.com",
                    "aud": "aws:marketplace",
                    "iat": 1700000000,
                    "exp": 1700000300,
                    "jti": f"verify-test-{i}",
                    "price": {"amount": "1.00", "currency": "USD"},
                    "payTo": "seller-abc",
                    "reference": "TEST",
                }

                token = signer.sign_quote(payload)
                parts = token.split(".")

                # The message that was signed is header.payload (ASCII bytes).
                message = f"{parts[0]}.{parts[1]}".encode()

                # Decode the raw r||s signature back to DER for verification.
                raw_sig = _base64url_decode(parts[2])
                assert len(raw_sig) == 96  # P-384: 48 bytes r + 48 bytes s

                # Convert raw r||s back to integers, then to DER for the verify call.
                r = int.from_bytes(raw_sig[:48], byteorder="big")
                s = int.from_bytes(raw_sig[48:], byteorder="big")
                der_sig = encode_dss_signature(r, s)

                # Verify against the public key — raises InvalidSignature on failure.
                public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA384()))

    def test_kms_error_raises_signing_error(self) -> None:
        """If the KMS client raises, we wrap it in SigningError."""
        with mock_aws():
            client = boto3.client("kms", region_name="us-east-1")
            key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
            key_arn = key["KeyMetadata"]["Arn"]

            config = KmsQuoteSignerConfig(
                key_arn=key_arn,
                region="us-east-1",
                service_url="https://api.example.com",
                _kms_client=client,
            )
            signer = KmsQuoteSigner(config)

            # Monkeypatch sign to raise.
            def _raise_error(**_kwargs: object) -> None:
                raise RuntimeError("KMS unavailable")

            signer._kms_client.sign = _raise_error

            with pytest.raises(SigningError, match="KMS Sign API call failed"):
                signer.sign_quote({"iss": "test"})

    def test_empty_signature_raises_signing_error(self) -> None:
        """If KMS returns an empty signature, we raise SigningError."""
        with mock_aws():
            client = boto3.client("kms", region_name="us-east-1")
            key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
            key_arn = key["KeyMetadata"]["Arn"]

            config = KmsQuoteSignerConfig(
                key_arn=key_arn,
                region="us-east-1",
                service_url="https://api.example.com",
                _kms_client=client,
            )
            signer = KmsQuoteSigner(config)

            # Return a response with an empty signature.
            def _empty_signature(**_kwargs: object) -> dict[str, bytes]:
                return {"Signature": b""}

            signer._kms_client.sign = _empty_signature

            with pytest.raises(SigningError, match="KMS Sign returned no signature"):
                signer.sign_quote({"iss": "test"})


class TestKmsSignerAccessors:
    """Tests for get_service_url."""

    @mock_aws
    def test_get_service_url(self) -> None:
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(KeySpec="ECC_NIST_P384", KeyUsage="SIGN_VERIFY")
        key_arn = key["KeyMetadata"]["Arn"]

        config = KmsQuoteSignerConfig(
            key_arn=key_arn,
            region="us-east-1",
            service_url="https://my-service.example.com",
            _kms_client=client,
        )
        signer = KmsQuoteSigner(config)
        assert signer.get_service_url() == "https://my-service.example.com"


class TestDerToRaw:
    """Tests for _der_to_raw conversion."""

    def test_p384_conversion(self) -> None:
        """Generate a real P-384 signature, convert DER->raw, verify lengths."""
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        private_key = ec.generate_private_key(ec.SECP384R1())
        message = b"test data"
        der_sig = private_key.sign(message, ec.ECDSA(hashes.SHA384()))

        raw = _der_to_raw(der_sig, 48)
        assert len(raw) == 96

        # Verify roundtrip: convert raw back and verify.
        r = int.from_bytes(raw[:48], byteorder="big")
        s = int.from_bytes(raw[48:], byteorder="big")
        reconstructed_der = encode_dss_signature(r, s)

        public_key = private_key.public_key()
        public_key.verify(reconstructed_der, message, ec.ECDSA(hashes.SHA384()))

    def test_p256_conversion(self) -> None:
        """Ensure conversion works for P-256 (32-byte components) too."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        message = b"p256 test"
        der_sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

        raw = _der_to_raw(der_sig, 32)
        assert len(raw) == 64


class TestBase64urlEncode:
    """Tests for _base64url_encode helper."""

    def test_no_padding(self) -> None:
        result = _base64url_encode(b"hello")
        assert "=" not in result

    def test_url_safe_chars(self) -> None:
        # Data that would produce + and / in standard base64.
        data = bytes(range(256))
        result = _base64url_encode(data)
        assert "+" not in result
        assert "/" not in result
