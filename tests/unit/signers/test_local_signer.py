# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the in-process quote signer."""

from __future__ import annotations

import json
from typing import Any, Optional

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from fiat_extension_x402.exceptions import SigningError
from fiat_extension_x402.signers import LocalQuoteSigner, QuoteSigner
from tests.support import SELLER_URL, ec_key


class TestLocalQuoteSigner:
    def test_satisfies_protocol(self) -> None:
        key, jwk = ec_key("seller-key")
        assert isinstance(LocalQuoteSigner(key, jwk, SELLER_URL), QuoteSigner)

    def test_accessors(self) -> None:
        key, jwk = ec_key("seller-key")
        signer = LocalQuoteSigner(key, jwk, SELLER_URL)
        assert signer.public_jwk is jwk
        assert signer.get_service_url() == SELLER_URL

    @pytest.mark.parametrize("service_url", ["", "  "])
    def test_empty_service_url_raises(self, service_url: str) -> None:
        key, jwk = ec_key("seller-key")
        with pytest.raises(SigningError, match="service_url is required"):
            LocalQuoteSigner(key, jwk, service_url)

    def test_signs_with_jwk_alg_and_kid(self) -> None:
        key, jwk = ec_key("seller-p384", ec.SECP384R1(), "ES384")
        token = LocalQuoteSigner(key, jwk, SELLER_URL).sign_quote({"iss": SELLER_URL})
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "ES384"
        assert header["kid"] == "seller-p384"
        claims = jwt.decode(token, key.public_key(), algorithms=["ES384"])
        assert claims == {"iss": SELLER_URL}

    def test_defaults_to_es256_without_kid(self) -> None:
        key, jwk = ec_key("unused")
        public_jwk = {k: v for k, v in jwk.items() if k not in ("alg", "kid")}
        token = LocalQuoteSigner(key, public_jwk, SELLER_URL).sign_quote({"a": 1})
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "ES256"
        assert "kid" not in header

    def test_rsa_key(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        public_jwk.update(alg="RS256", kid="seller-rsa")
        token = LocalQuoteSigner(key, public_jwk, SELLER_URL).sign_quote({"a": 1})
        assert jwt.decode(token, key.public_key(), algorithms=["RS256"]) == {"a": 1}

    @pytest.mark.parametrize("member", ["d", "k"])
    def test_rejects_private_material_in_public_jwk(self, member: str) -> None:
        key, jwk = ec_key("seller-key")
        with pytest.raises(SigningError, match="private key members"):
            LocalQuoteSigner(key, {**jwk, member: "secret"}, SELLER_URL)


def _pem(key: Any, password: Optional[bytes] = None) -> bytes:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(  # type: ignore[no-any-return]
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


class TestFromPem:
    @pytest.mark.parametrize(
        ("curve", "alg"),
        [(ec.SECP256R1(), "ES256"), (ec.SECP384R1(), "ES384"), (ec.SECP521R1(), "ES512")],
    )
    def test_ec_key(self, curve: ec.EllipticCurve, alg: str) -> None:
        key = ec.generate_private_key(curve)
        signer = LocalQuoteSigner.from_pem(_pem(key), kid="k1", service_url=SELLER_URL)

        assert signer.public_jwk["alg"] == alg
        assert signer.public_jwk["kid"] == "k1"
        assert signer.public_jwk["use"] == "sig"
        assert "d" not in signer.public_jwk
        token = signer.sign_quote({"a": 1})
        assert jwt.get_unverified_header(token)["kid"] == "k1"
        public_key = jwt.PyJWK.from_dict(signer.public_jwk).key
        assert jwt.decode(token, public_key, algorithms=[alg]) == {"a": 1}

    def test_rsa_key_from_str(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        signer = LocalQuoteSigner.from_pem(_pem(key).decode(), kid="r1", service_url=SELLER_URL)

        assert signer.public_jwk["alg"] == "RS256"
        assert signer.public_jwk["kty"] == "RSA"
        token = signer.sign_quote({"a": 1})
        assert jwt.decode(token, key.public_key(), algorithms=["RS256"]) == {"a": 1}

    def test_encrypted_pem(self) -> None:
        key = ec.generate_private_key(ec.SECP384R1())
        pem = _pem(key, b"pass-phrase")
        signer = LocalQuoteSigner.from_pem(
            pem, kid="k1", service_url=SELLER_URL, password=b"pass-phrase"
        )
        assert signer.public_jwk["alg"] == "ES384"

    def test_wrong_password(self) -> None:
        pem = _pem(ec.generate_private_key(ec.SECP384R1()), b"pass-phrase")
        with pytest.raises(SigningError, match="Could not load"):
            LocalQuoteSigner.from_pem(pem, kid="k1", service_url=SELLER_URL, password=b"no")

    def test_not_a_pem(self) -> None:
        with pytest.raises(SigningError, match="Could not load"):
            LocalQuoteSigner.from_pem(b"not a key", kid="k1", service_url=SELLER_URL)

    @pytest.mark.parametrize("kid", ["", "  "])
    def test_empty_kid(self, kid: str) -> None:
        pem = _pem(ec.generate_private_key(ec.SECP256R1()))
        with pytest.raises(SigningError, match="kid is required"):
            LocalQuoteSigner.from_pem(pem, kid=kid, service_url=SELLER_URL)

    def test_unsupported_curve(self) -> None:
        pem = _pem(ec.generate_private_key(ec.SECP256K1()))
        with pytest.raises(SigningError, match="Unsupported EC curve"):
            LocalQuoteSigner.from_pem(pem, kid="k1", service_url=SELLER_URL)

    def test_unsupported_key_type(self) -> None:
        pem = _pem(ed25519.Ed25519PrivateKey.generate())
        with pytest.raises(SigningError, match="Only EC and RSA"):
            LocalQuoteSigner.from_pem(pem, kid="k1", service_url=SELLER_URL)
