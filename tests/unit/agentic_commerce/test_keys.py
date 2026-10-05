# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the seller JWKS helper."""

from __future__ import annotations

import pytest

from fiat_extension_x402.agentic_commerce.keys import jwks_document
from fiat_extension_x402.exceptions import ValidationError
from tests.support import ec_key


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

    def test_requires_a_key(self) -> None:
        with pytest.raises(ValidationError, match="At least one public key"):
            jwks_document()

    @pytest.mark.parametrize("missing", ["kty", "kid"])
    def test_requires_kty_and_kid(self, missing: str) -> None:
        _, jwk = ec_key("current")
        del jwk[missing]
        with pytest.raises(ValidationError, match="needs 'kty' and 'kid'"):
            jwks_document(jwk)

    def test_rejects_duplicate_kid(self) -> None:
        _, first = ec_key("same")
        _, second = ec_key("same")
        with pytest.raises(ValidationError, match="Duplicate kid: same"):
            jwks_document(first, second)

    def test_rejects_private_material(self) -> None:
        _, jwk = ec_key("current")
        with pytest.raises(ValidationError, match=r"private key members: \['d'\]"):
            jwks_document({**jwk, "d": "secret"})
