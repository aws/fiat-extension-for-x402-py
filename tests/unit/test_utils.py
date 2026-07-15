# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for utils module."""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import patch

import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from httpx import Response

from fiat_extension_x402.exceptions import ExpiryError, SignatureError, ValidationError
from fiat_extension_x402.utils import (
    clear_service_jwks_cache,
    decode_quote_token,
    extract_network_from_transaction_id,
    extract_quote_from_payment,
    fetch_service_jwks,
    format_transaction_id,
    generate_transaction_id,
    is_valid_transaction_id,
    parse_money_to_decimal,
    parse_transaction_id,
    verify_payment_token,
    verify_quote_token,
)


class TestDecodeQuoteToken:
    def test_decodes(self) -> None:
        token = pyjwt.encode({"iss": "test", "foo": "bar"}, "secret", algorithm="HS256")
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
        payload = {"iss": "agentpay", "exp": int(time.time()) + 300}
        token = pyjwt.encode(payload, key, algorithm="ES256")
        claims = verify_payment_token(token, key.public_key())
        assert claims["iss"] == "agentpay"

    def test_expired(self) -> None:
        key = generate_private_key(SECP256R1())
        payload = {"iss": "test", "exp": int(time.time()) - 100}
        token = pyjwt.encode(payload, key, algorithm="ES256")
        with pytest.raises(ExpiryError):
            verify_payment_token(token, key.public_key())


class TestExtractQuoteFromPayment:
    def test_top_level(self) -> None:
        assert extract_quote_from_payment({"quote_token": "qt1"}) == "qt1"

    def test_nested(self) -> None:
        payment = {"payment_context": {"quote_token": "qt2"}}
        assert extract_quote_from_payment(payment) == "qt2"

    def test_missing(self) -> None:
        assert extract_quote_from_payment({}) == ""


class TestGenerateTransactionId:
    def test_format(self) -> None:
        tid = generate_transaction_id("aws:base", "agent-id")
        assert tid.startswith("aws:base:")
        parts = tid.split(":")
        assert len(parts[-1]) == 16


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


class TestParseTransactionId:
    def test_valid(self) -> None:
        result = parse_transaction_id("aws:base:abc123")
        assert result == {"network": "aws:base", "id": "abc123"}

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            parse_transaction_id("no-colon")


class TestFormatTransactionId:
    def test_valid(self) -> None:
        result = format_transaction_id("aws:base", "myid")
        assert result == "aws:base:myid"

    def test_invalid_network(self) -> None:
        with pytest.raises(ValidationError):
            format_transaction_id("nocolon", "id")


class TestIsValidTransactionId:
    def test_valid(self) -> None:
        assert is_valid_transaction_id("aws:base:abc") is True

    def test_invalid(self) -> None:
        assert is_valid_transaction_id("nocolon") is False


class TestExtractNetworkFromTransactionId:
    def test_extracts(self) -> None:
        assert extract_network_from_transaction_id("aws:base:id") == "aws:base"


class TestFetchServiceJwks:
    @respx.mock
    def test_fetches_and_caches(self) -> None:
        clear_service_jwks_cache()
        jwks: dict[str, Any] = {"keys": [{"kty": "EC", "kid": "1"}]}
        route = respx.get("https://service.example.com/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks)
        )
        result = fetch_service_jwks("https://service.example.com")
        assert result == jwks

        # Second call hits cache
        result2 = fetch_service_jwks("https://service.example.com")
        assert result2 == jwks
        assert route.call_count == 1

    @respx.mock
    def test_error_raises(self) -> None:
        clear_service_jwks_cache()
        respx.get("https://bad.example.com/.well-known/jwks.json").mock(
            return_value=Response(500, text="error")
        )
        with pytest.raises(ValidationError):
            fetch_service_jwks("https://bad.example.com")


class TestClearServiceJwksCache:
    @respx.mock
    def test_clear_all(self) -> None:
        clear_service_jwks_cache()
        jwks: dict[str, Any] = {"keys": []}
        respx.get("https://a.com/.well-known/jwks.json").mock(return_value=Response(200, json=jwks))
        fetch_service_jwks("https://a.com")
        clear_service_jwks_cache()
        # After clear, should fetch again
        respx.get("https://a.com/.well-known/jwks.json").mock(return_value=Response(200, json=jwks))
        fetch_service_jwks("https://a.com")

    @respx.mock
    def test_clear_specific(self) -> None:
        clear_service_jwks_cache()
        jwks: dict[str, Any] = {"keys": []}
        respx.get("https://b.com/.well-known/jwks.json").mock(return_value=Response(200, json=jwks))
        fetch_service_jwks("https://b.com")
        clear_service_jwks_cache("https://b.com")


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
        with patch("fiat_extension_x402.utils.pyjwt.decode", side_effect=pyjwt.DecodeError("boom")):
            with pytest.raises(SignatureError, match="verification failed"):
                verify_quote_token(token, key.public_key())

    def test_verify_payment_token_invalid_signature(self) -> None:
        """A bad signature raises SignatureError (line 85-86)."""
        key1 = generate_private_key(SECP256R1())
        key2 = generate_private_key(SECP256R1())
        token = pyjwt.encode({"iss": "agentpay"}, key1, algorithm="ES256")
        with pytest.raises(SignatureError, match="signature invalid"):
            verify_payment_token(token, key2.public_key())

    def test_verify_payment_token_generic_pyjwt_error(self) -> None:
        """A non-signature PyJWTError (e.g. DecodeError) raises SignatureError (line 87-88)."""
        key = generate_private_key(SECP256R1())
        token = pyjwt.encode({"iss": "agentpay"}, key, algorithm="ES256")
        with patch("fiat_extension_x402.utils.pyjwt.decode", side_effect=pyjwt.DecodeError("boom")):
            with pytest.raises(SignatureError, match="verification failed"):
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


class TestGenerateTransactionIdEdgeCases:
    """Edge cases for generate_transaction_id."""

    def test_unique_ids(self) -> None:
        tid1 = generate_transaction_id("fab:aws", "agent-pay-123")
        tid2 = generate_transaction_id("fab:aws", "agent-pay-123")
        assert tid1 != tid2

    def test_different_network_formats(self) -> None:
        import re

        assert re.match(r"^fab:aws:[a-f0-9]{16}$", generate_transaction_id("fab:aws", "a"))
        assert re.match(r"^fab:google:[a-f0-9]{16}$", generate_transaction_id("fab:google", "b"))
        assert re.match(
            r"^fab:custom:network:[a-f0-9]{16}$",
            generate_transaction_id("fab:custom:network", "c"),
        )

    def test_exactly_16_hex_chars(self) -> None:
        import re

        tid = generate_transaction_id("fab:test", "agent-pay")
        id_part = tid.split(":")[-1]
        assert len(id_part) == 16
        assert re.match(r"^[a-f0-9]{16}$", id_part)


class TestParseTransactionIdEdgeCases:
    """Edge cases for parse_transaction_id."""

    def test_nested_colons(self) -> None:
        assert parse_transaction_id("fab:aws:us-east-1:abc123") == {
            "network": "fab:aws:us-east-1",
            "id": "abc123",
        }

    def test_any_scheme(self) -> None:
        assert parse_transaction_id("aws:abc123") == {"network": "aws", "id": "abc123"}
        assert parse_transaction_id("evm:eth:abc123") == {"network": "evm:eth", "id": "abc123"}

    def test_very_long_network(self) -> None:
        assert parse_transaction_id("fab:aws:us-east-1:prod:service:abc123") == {
            "network": "fab:aws:us-east-1:prod:service",
            "id": "abc123",
        }

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError):
            parse_transaction_id("")

    def test_single_colon_raises(self) -> None:
        with pytest.raises(ValidationError):
            parse_transaction_id("fab:")

    def test_detailed_error_message(self) -> None:
        with pytest.raises(ValidationError, match="Invalid transaction ID format"):
            parse_transaction_id("invalid-format")


class TestFormatTransactionIdEdgeCases:
    """Edge cases for format_transaction_id."""

    def test_any_scheme(self) -> None:
        assert format_transaction_id("evm:eth", "abc123") == "evm:eth:abc123"

    def test_complex_network(self) -> None:
        assert format_transaction_id("fab:aws:us-east-1:prod", "abc123") == (
            "fab:aws:us-east-1:prod:abc123"
        )

    def test_detailed_error_for_invalid_network(self) -> None:
        with pytest.raises(ValidationError, match="scheme:provider format"):
            format_transaction_id("invalid", "abc123")


class TestIsValidTransactionIdComprehensive:
    """Comprehensive cases for is_valid_transaction_id."""

    def test_valid_with_any_network(self) -> None:
        assert is_valid_transaction_id("aws:abc123") is True
        assert is_valid_transaction_id("evm:eth:abc123") is True

    def test_empty_and_whitespace(self) -> None:
        assert is_valid_transaction_id("") is False
        assert is_valid_transaction_id(" ") is False
        assert is_valid_transaction_id("   ") is False

    def test_malformed(self) -> None:
        assert is_valid_transaction_id("fab") is False
        assert is_valid_transaction_id("fab:") is False
        assert is_valid_transaction_id(":abc123") is False
        # "fab::abc123" is valid — network is "fab:" and id is "abc123"
        assert is_valid_transaction_id("fab::abc123") is True

    def test_strict_valid(self) -> None:
        assert is_valid_transaction_id("fab:aws:abc") is True
        assert is_valid_transaction_id("fab:test:123") is True
        assert is_valid_transaction_id("fab:a:b:c:d") is True


class TestExtractNetworkEdgeCases:
    """Edge cases for extract_network_from_transaction_id."""

    def test_minimal_valid(self) -> None:
        assert extract_network_from_transaction_id("fab:x:y") == "fab:x"

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValidationError):
            extract_network_from_transaction_id("fab")
        with pytest.raises(ValidationError):
            extract_network_from_transaction_id("nocolon")

    def test_any_scheme(self) -> None:
        assert extract_network_from_transaction_id("notfab:aws:123") == "notfab:aws"


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
