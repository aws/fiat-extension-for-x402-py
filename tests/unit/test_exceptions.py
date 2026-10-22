# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for exception classes."""

from __future__ import annotations

from fiat_extension_x402.exceptions import (
    AgenticCommerceError,
    DPoPError,
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


class TestErrorInheritance:
    def test_catch_all_as_agentic_commerce_error(self) -> None:
        errors = [
            ValidationError("test"),
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
        assert not isinstance(err, SigningError)
