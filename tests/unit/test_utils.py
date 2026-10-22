# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for utils module."""

from __future__ import annotations

import jwt as pyjwt
import pytest

from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.utils import decode_quote_token


class TestDecodeQuoteToken:
    def test_decodes(self) -> None:
        token = pyjwt.encode(
            {"iss": "test", "foo": "bar"},
            "a-shared-secret-that-is-at-least-32-bytes",
            algorithm="HS256",
        )
        claims = decode_quote_token(token)
        assert claims["iss"] == "test"
        assert claims["foo"] == "bar"

    def test_invalid_token(self) -> None:
        with pytest.raises(ValidationError):
            decode_quote_token("invalid")


class TestDecodeQuoteTokenMessage:
    """The decode error message matches the reference wording."""

    def test_invalid_format_message(self) -> None:
        with pytest.raises(ValidationError, match="Invalid quote token format"):
            decode_quote_token("not.a.jwt")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError):
            decode_quote_token("")


@pytest.mark.parametrize(
    "name",
    ["verify_payment_token", "verify_quote_token", "parse_money_to_decimal"],
)
def test_removed_helpers_are_not_public(name: str) -> None:
    """Removed helpers stay removed; AgenticCommerceVerifier verifies tokens."""
    import fiat_extension_x402
    from fiat_extension_x402 import utils

    assert not hasattr(utils, name)
    assert not hasattr(fiat_extension_x402, name)
