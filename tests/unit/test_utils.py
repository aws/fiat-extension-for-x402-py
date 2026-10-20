# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for utils module."""

from __future__ import annotations

import jwt as pyjwt
import pytest

from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.utils import decode_quote_token, parse_money_to_decimal


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


class TestParseMoneyToDecimal:
    def test_dollar_sign(self) -> None:
        result = parse_money_to_decimal("$1.50")
        assert result == {"amount": 1.50, "currency": "USD"}

    def test_with_currency(self) -> None:
        result = parse_money_to_decimal("2.99 EUR")
        assert result == {"amount": 2.99, "currency": "EUR"}

    def test_numeric(self) -> None:
        result = parse_money_to_decimal(10)
        assert result == {"amount": 10.0, "currency": "USD"}

    def test_float(self) -> None:
        result = parse_money_to_decimal(3.14)
        assert result == {"amount": 3.14, "currency": "USD"}


class TestUtilsAdditional:
    """Cover remaining paths in utils.py."""

    def test_parse_money_bare_numeric_string(self) -> None:
        """parse_money_to_decimal handles bare numeric string."""
        result = parse_money_to_decimal("7.99")
        assert result == {"amount": 7.99, "currency": "USD"}


class TestParseMoneyEdgeCases:
    """Edge cases for parse_money_to_decimal."""

    def test_integer_amounts(self) -> None:
        assert parse_money_to_decimal("5") == {"amount": 5.0, "currency": "USD"}
        assert parse_money_to_decimal("$10") == {"amount": 10.0, "currency": "USD"}

    def test_many_decimal_places(self) -> None:
        assert parse_money_to_decimal("1.999") == {"amount": 1.999, "currency": "USD"}
        assert parse_money_to_decimal("$0.01") == {"amount": 0.01, "currency": "USD"}

    def test_zero_amounts(self) -> None:
        assert parse_money_to_decimal(0) == {"amount": 0.0, "currency": "USD"}
        assert parse_money_to_decimal("$0") == {"amount": 0.0, "currency": "USD"}
        assert parse_money_to_decimal("0.00 EUR") == {"amount": 0.0, "currency": "EUR"}

    def test_negative_amounts_raise(self) -> None:
        with pytest.raises(ValidationError):
            parse_money_to_decimal("-1.50")
        with pytest.raises(ValidationError):
            parse_money_to_decimal("$-5")

    def test_invalid_currency_codes_raise(self) -> None:
        with pytest.raises(ValidationError):
            parse_money_to_decimal("1.50 US")
        with pytest.raises(ValidationError):
            parse_money_to_decimal("1.50 USDD")

    def test_malformed_strings_raise(self) -> None:
        for bad in ("$", "USD", "1.50.50", "1,50", "invalid", "USD 1.50"):
            with pytest.raises(ValidationError):
                parse_money_to_decimal(bad)

    @pytest.mark.parametrize("money", [True, False])
    def test_booleans_raise(self, money: bool) -> None:
        with pytest.raises(ValidationError, match="Invalid money format"):
            parse_money_to_decimal(money)

    @pytest.mark.parametrize("money", ["\u0661.\u0665\u0660", "$1.\u0665", "\uff11 USD"])
    def test_non_ascii_digits_raise(self, money: str) -> None:
        with pytest.raises(ValidationError, match="Invalid money format"):
            parse_money_to_decimal(money)


class TestDecodeQuoteTokenMessage:
    """The decode error message matches the reference wording."""

    def test_invalid_format_message(self) -> None:
        with pytest.raises(ValidationError, match="Invalid quote token format"):
            decode_quote_token("not.a.jwt")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError):
            decode_quote_token("")


@pytest.mark.parametrize("name", ["verify_payment_token", "verify_quote_token"])
def test_partial_token_verifiers_are_not_public(name: str) -> None:
    """Only AgenticCommerceVerifier verifies tokens: these checked signatures alone."""
    import fiat_extension_x402
    from fiat_extension_x402 import utils

    assert not hasattr(utils, name)
    assert not hasattr(fiat_extension_x402, name)
