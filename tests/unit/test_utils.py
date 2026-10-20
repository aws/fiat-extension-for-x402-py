# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for utils module."""

from __future__ import annotations

import time
from unittest.mock import patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

from fiat_extension_x402.exceptions import ExpiryError, SignatureError, ValidationError
from fiat_extension_x402.utils import (
    decode_quote_token,
    parse_money_to_decimal,
    verify_payment_token,
    verify_quote_token,
)


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


class TestVerifyQuoteToken:
    def test_valid(self) -> None:
        key = generate_private_key(SECP256R1())
        payload = {"iss": "test", "exp": int(time.time()) + 300}
        token = pyjwt.encode(payload, key, algorithm="ES256")
        claims = verify_quote_token(token, key.public_key())
        assert claims["iss"] == "test"

    def test_expired(self) -> None:
        key = generate_private_key(SECP256R1())
        payload = {"iss": "test", "exp": int(time.time()) - 100}
        token = pyjwt.encode(payload, key, algorithm="ES256")
        with pytest.raises(ExpiryError):
            verify_quote_token(token, key.public_key())

    def test_bad_signature(self) -> None:
        key1 = generate_private_key(SECP256R1())
        key2 = generate_private_key(SECP256R1())
        payload = {"iss": "test", "exp": int(time.time()) + 300}
        token = pyjwt.encode(payload, key1, algorithm="ES256")
        with pytest.raises(SignatureError):
            verify_quote_token(token, key2.public_key())


class TestVerifyPaymentToken:
    def test_valid(self) -> None:
        key = generate_private_key(SECP256R1())
        payload = {"iss": "payment-service", "exp": int(time.time()) + 300}
        token = pyjwt.encode(payload, key, algorithm="ES256")
        claims = verify_payment_token(token, key.public_key())
        assert claims["iss"] == "payment-service"

    def test_expired(self) -> None:
        key = generate_private_key(SECP256R1())
        payload = {"iss": "test", "exp": int(time.time()) - 100}
        token = pyjwt.encode(payload, key, algorithm="ES256")
        with pytest.raises(ExpiryError):
            verify_payment_token(token, key.public_key())


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

    def test_verify_quote_token_invalid_signature(self) -> None:
        """A bad signature raises SignatureError (line 53-54)."""
        key1 = generate_private_key(SECP256R1())
        key2 = generate_private_key(SECP256R1())
        token = pyjwt.encode({"iss": "test"}, key1, algorithm="ES256")
        with pytest.raises(SignatureError, match="signature invalid"):
            verify_quote_token(token, key2.public_key())

    def test_verify_quote_token_generic_pyjwt_error(self) -> None:
        """A non-signature PyJWTError (e.g. DecodeError) raises SignatureError (line 55-56)."""
        key = generate_private_key(SECP256R1())
        token = pyjwt.encode({"iss": "test"}, key, algorithm="ES256")
        with (
            patch("fiat_extension_x402.utils.pyjwt.decode", side_effect=pyjwt.DecodeError("boom")),
            pytest.raises(SignatureError, match="verification failed"),
        ):
            verify_quote_token(token, key.public_key())

    def test_verify_payment_token_invalid_signature(self) -> None:
        """A bad signature raises SignatureError (line 85-86)."""
        key1 = generate_private_key(SECP256R1())
        key2 = generate_private_key(SECP256R1())
        token = pyjwt.encode({"iss": "payment-service"}, key1, algorithm="ES256")
        with pytest.raises(SignatureError, match="signature invalid"):
            verify_payment_token(token, key2.public_key())

    def test_verify_payment_token_generic_pyjwt_error(self) -> None:
        """A non-signature PyJWTError (e.g. DecodeError) raises SignatureError (line 87-88)."""
        key = generate_private_key(SECP256R1())
        token = pyjwt.encode({"iss": "payment-service"}, key, algorithm="ES256")
        with (
            patch("fiat_extension_x402.utils.pyjwt.decode", side_effect=pyjwt.DecodeError("boom")),
            pytest.raises(SignatureError, match="verification failed"),
        ):
            verify_payment_token(token, key.public_key())

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


class TestVerifyQuoteTokenInvalidSignature:
    """Cover the InvalidSignatureError path (line 53-54 of utils.py)."""

    def test_invalid_signature_raises_signature_error(self) -> None:
        key1 = generate_private_key(SECP256R1())
        key2 = generate_private_key(SECP256R1())
        payload = {"iss": "test", "exp": int(time.time()) + 300}
        token = pyjwt.encode(payload, key1, algorithm="ES256")
        # Verify with wrong key — should hit InvalidSignatureError specifically
        with pytest.raises(SignatureError, match="signature invalid"):
            verify_quote_token(token, key2.public_key())


class TestVerifyPaymentTokenInvalidSignature:
    """Cover the InvalidSignatureError path (line 85-86 of utils.py)."""

    def test_invalid_signature_raises_signature_error(self) -> None:
        key1 = generate_private_key(SECP256R1())
        key2 = generate_private_key(SECP256R1())
        payload = {"iss": "test", "exp": int(time.time()) + 300}
        token = pyjwt.encode(payload, key1, algorithm="ES256")
        with pytest.raises(SignatureError, match="signature invalid"):
            verify_payment_token(token, key2.public_key())


class TestTokensWithoutExpiry:
    """Tokens without an ``exp`` claim are accepted (expiry is optional here)."""

    def test_quote_token_without_exp(self) -> None:
        key = generate_private_key(SECP256R1())
        token = pyjwt.encode({"iss": "test"}, key, algorithm="ES256")
        assert verify_quote_token(token, key.public_key()) == {"iss": "test"}

    def test_payment_token_without_exp(self) -> None:
        key = generate_private_key(SECP256R1())
        token = pyjwt.encode({"iss": "test"}, key, algorithm="ES256")
        assert verify_payment_token(token, key.public_key()) == {"iss": "test"}

    def test_hs256_token_is_rejected(self) -> None:
        token = pyjwt.encode(
            {"iss": "test"}, "a-shared-secret-that-is-at-least-32-bytes", algorithm="HS256"
        )
        with pytest.raises(SignatureError, match="verification failed"):
            verify_quote_token(token, "a-shared-secret-that-is-at-least-32-bytes")
