# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the in-process quote signer."""

from __future__ import annotations

import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

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
