# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for exception classes."""

from __future__ import annotations

from fiat_extension_x402.exceptions import (
    AgenticCommerceError,
    DPoPError,
    ExpiryError,
    MismatchError,
    SignatureError,
    SigningError,
    ValidationError,
)


class TestAgenticCommerceError:
    def test_message_code_and_details(self) -> None:
        err = AgenticCommerceError("Test error", "TEST_ERROR", {"field": "value"})
        assert str(err) == "Test error"
        assert err.code == "TEST_ERROR"
        assert err.details == {"field": "value"}
        assert type(err).__name__ == "AgenticCommerceError"
        assert isinstance(err, Exception)

    def test_without_details(self) -> None:
        err = AgenticCommerceError("Test error", "TEST_ERROR")
        assert str(err) == "Test error"
        assert err.code == "TEST_ERROR"
        assert err.details is None


class TestValidationError:
    def test_with_details(self) -> None:
        err = ValidationError("Invalid field", {"field": "amount", "value": "abc"})
        assert str(err) == "Invalid field"
        assert err.code == "VALIDATION_ERROR"
        assert err.details == {"field": "amount", "value": "abc"}
        assert type(err).__name__ == "ValidationError"
        assert isinstance(err, AgenticCommerceError)

    def test_without_details(self) -> None:
        err = ValidationError("Invalid format")
        assert str(err) == "Invalid format"
        assert err.code == "VALIDATION_ERROR"
        assert err.details is None


class TestSigningError:
    def test_with_details(self) -> None:
        err = SigningError("KMS failed", {"supported": ["ECDSA_SHA_384"]})
        assert str(err) == "KMS failed"
        assert err.code == "SIGNING_ERROR"
        assert err.details == {"supported": ["ECDSA_SHA_384"]}
        assert isinstance(err, AgenticCommerceError)

    def test_without_details(self) -> None:
        err = SigningError("KMS failed")
        assert err.code == "SIGNING_ERROR"
        assert err.details is None


class TestDPoPError:
    def test_attributes(self) -> None:
        err = DPoPError("bad proof", {"jti": "abc"})
        assert str(err) == "bad proof"
        assert err.code == "DPOP_ERROR"
        assert err.details == {"jti": "abc"}

    def test_without_details(self) -> None:
        assert DPoPError("bad proof").details is None


class TestSignatureError:
    def test_attributes(self) -> None:
        err = SignatureError("bad sig", "quote")
        assert err.code == "SIGNATURE_ERROR"
        assert err.token_type == "quote"
        assert err.details == {"token_type": "quote"}
        assert "bad sig" in str(err)

    def test_payment_variant(self) -> None:
        err = SignatureError("Invalid signature", "payment")
        assert str(err) == "Invalid signature"
        assert err.token_type == "payment"
        assert err.details == {"token_type": "payment"}

    def test_is_agentic_commerce_error(self) -> None:
        assert issubclass(SignatureError, AgenticCommerceError)


class TestExpiryError:
    def test_attributes(self) -> None:
        err = ExpiryError("token expired", 1000, 2000)
        assert err.code == "EXPIRY_ERROR"
        assert err.expiry == 1000
        assert err.current_time == 2000
        assert err.details == {"expiry": 1000, "current_time": 2000}

    def test_is_agentic_commerce_error(self) -> None:
        assert issubclass(ExpiryError, AgenticCommerceError)


class TestMismatchError:
    def test_attributes(self) -> None:
        err = MismatchError("mismatch", "foo", "bar")
        assert err.code == "MISMATCH_ERROR"
        assert err.expected == "foo"
        assert err.actual == "bar"
        assert err.details == {"expected": "foo", "actual": "bar"}

    def test_complex_objects(self) -> None:
        expected = {"amount": "0.15", "currency": "USD"}
        actual = {"amount": "0.20", "currency": "USD"}
        err = MismatchError("Price mismatch", expected, actual)  # type: ignore[arg-type]
        assert err.details == {"expected": expected, "actual": actual}

    def test_is_agentic_commerce_error(self) -> None:
        assert issubclass(MismatchError, AgenticCommerceError)


class TestErrorInheritance:
    def test_catch_all_as_agentic_commerce_error(self) -> None:
        errors = [
            ValidationError("test"),
            SignatureError("test", "quote"),
            ExpiryError("test", 123, 456),
            MismatchError("test", "a", "b"),
            DPoPError("test"),
            SigningError("test"),
        ]
        for err in errors:
            assert isinstance(err, AgenticCommerceError)
            assert isinstance(err, Exception)

    def test_catch_specific_type(self) -> None:
        err = ValidationError("test")
        assert isinstance(err, ValidationError)
        assert isinstance(err, AgenticCommerceError)
        assert not isinstance(err, SignatureError)
