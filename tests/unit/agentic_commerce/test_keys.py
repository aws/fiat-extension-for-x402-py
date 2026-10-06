# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the seller JWKS helper."""

from __future__ import annotations

from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from fiat_extension_x402.agentic_commerce.keys import jwks_document
from fiat_extension_x402.exceptions import ValidationError
from tests.support import ec_key


def _rsa_jwk(bits: int, **extra: Any) -> dict[str, Any]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    jwk: dict[str, Any] = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return {**jwk, "kid": f"rsa-{bits}", **extra}


class TestJwksDocument:
    def test_single_key(self) -> None:
        _, jwk = ec_key("current")
        document = jwks_document(jwk)
        assert document == {"keys": [jwk]}
        assert document["keys"][0] is not jwk

    def test_rotation_keeps_order(self) -> None:
        _, current = ec_key("current")
        _, previous = ec_key("previous")
        assert jwks_document(current, previous) == {"keys": [current, previous]}

    @pytest.mark.parametrize(
        ("curve", "alg"),
        [(ec.SECP256R1(), "ES256"), (ec.SECP384R1(), "ES384"), (ec.SECP521R1(), "ES512")],
    )
    def test_supported_ec_curves(self, curve: ec.EllipticCurve, alg: str) -> None:
        public = ec.generate_private_key(curve).public_key()
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(public, as_dict=True) | {"kid": "k", "alg": alg}
        assert jwks_document(jwk) == {"keys": [jwk]}

    def test_alg_and_use_are_optional(self) -> None:
        _, jwk = ec_key("current")
        del jwk["alg"]
        assert jwks_document(jwk) == {"keys": [jwk]}
        assert jwks_document({**jwk, "use": "sig"})["keys"][0]["use"] == "sig"

    def test_rsa_2048(self) -> None:
        jwk = _rsa_jwk(2048, alg="RS256")
        assert jwks_document(jwk) == {"keys": [jwk]}

    def test_requires_a_key(self) -> None:
        with pytest.raises(ValidationError, match="At least one public key"):
            jwks_document()

    @pytest.mark.parametrize("kid", [None, "", "  ", 123])
    def test_requires_a_string_kid(self, kid: Any) -> None:
        _, jwk = ec_key("current")
        jwk = (
            {**jwk, "kid": kid} if kid is not None else {k: v for k, v in jwk.items() if k != "kid"}
        )
        with pytest.raises(ValidationError, match="non-empty string 'kid'"):
            jwks_document(jwk)

    def test_rejects_duplicate_kid(self) -> None:
        _, first = ec_key("same")
        _, second = ec_key("same")
        with pytest.raises(ValidationError, match="Duplicate kid: same"):
            jwks_document(first, second)

    def test_rejects_private_material(self) -> None:
        _, jwk = ec_key("current")
        with pytest.raises(ValidationError, match=r"private key members \['d'\]"):
            jwks_document({**jwk, "d": "secret"})

    @pytest.mark.parametrize("kty", [None, "OKP", "oct-like"])
    def test_rejects_unsupported_key_type(self, kty: Any) -> None:
        _, jwk = ec_key("current")
        jwk = (
            {**jwk, "kty": kty} if kty is not None else {k: v for k, v in jwk.items() if k != "kty"}
        )
        with pytest.raises(ValidationError, match="kty must be 'EC' or 'RSA'"):
            jwks_document(jwk)

    @pytest.mark.parametrize("crv", [None, "secp256k1", "P-192"])
    def test_rejects_unsupported_curve(self, crv: Any) -> None:
        _, jwk = ec_key("current")
        jwk = (
            {**jwk, "crv": crv} if crv is not None else {k: v for k, v in jwk.items() if k != "crv"}
        )
        with pytest.raises(ValidationError, match="unsupported EC curve"):
            jwks_document(jwk)

    @pytest.mark.parametrize("alg", ["HS256", "ES384", "none", "RS256"])
    def test_rejects_alg_that_does_not_match_the_key(self, alg: str) -> None:
        _, jwk = ec_key("current")  # P-256 → ES256
        with pytest.raises(ValidationError, match="does not match the key"):
            jwks_document({**jwk, "alg": alg})

    def test_rejects_non_signing_use(self) -> None:
        _, jwk = ec_key("current")
        with pytest.raises(ValidationError, match="use must be 'sig'"):
            jwks_document({**jwk, "use": "enc"})

    @pytest.mark.parametrize(
        "change",
        [
            {"x": "AAAA"},  # wrong coordinate length
            {"x": "!!not-base64!!"},
            {"y": None},  # missing coordinate
        ],
    )
    def test_rejects_invalid_ec_key_material(self, change: dict[str, Any]) -> None:
        _, jwk = ec_key("current")
        jwk = {k: v for k, v in {**jwk, **change}.items() if v is not None}
        with pytest.raises(ValidationError, match="invalid key material"):
            jwks_document(jwk)

    def test_rejects_ec_point_not_on_the_curve(self) -> None:
        _, jwk = ec_key("current")
        _, other = ec_key("other")
        with pytest.raises(ValidationError, match="invalid key material"):
            jwks_document({**jwk, "y": other["y"]})

    def test_rejects_short_rsa_key(self) -> None:
        with pytest.raises(ValidationError, match="at least 2048 bits, got 1024"):
            jwks_document(_rsa_jwk(1024))

    def test_rejects_rsa_without_modulus(self) -> None:
        jwk = {k: v for k, v in _rsa_jwk(2048).items() if k != "n"}
        with pytest.raises(ValidationError, match="invalid key material"):
            jwks_document(jwk)
