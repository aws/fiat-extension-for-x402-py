# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for security module."""

from __future__ import annotations

import pytest

from fiat_extension_x402.security import ALLOWED_ALGORITHMS, secure_compare, validate_url


class TestAllowedAlgorithms:
    def test_value(self) -> None:
        assert ALLOWED_ALGORITHMS == ["RS256", "ES256", "ES384", "ES512"]

    def test_excludes_insecure_algorithms(self) -> None:
        for insecure in ("none", "HS256", "HS384", "HS512"):
            assert insecure not in ALLOWED_ALGORITHMS


class TestSecureCompare:
    def test_equal_strings(self) -> None:
        assert secure_compare("hello", "hello") is True
        assert secure_compare("awsmp-123-456", "awsmp-123-456") is True

    def test_different_strings(self) -> None:
        assert secure_compare("hello", "world") is False
        assert secure_compare("awsmp-123", "awsmp-456") is False

    def test_different_lengths(self) -> None:
        assert secure_compare("short", "longer string") is False
        assert secure_compare("", "notempty") is False

    def test_empty_strings(self) -> None:
        assert secure_compare("", "") is True

    def test_jwt_length_strings(self) -> None:
        jwt1 = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhd3MtbWFya2V0cGxhY2UifQ.signature"
        jwt2 = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhd3MtbWFya2V0cGxhY2UifQ.signature"
        jwt3 = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJhd3MtbWFya2V0cGxhY2UifQ.different"
        assert secure_compare(jwt1, jwt2) is True
        assert secure_compare(jwt1, jwt3) is False


class TestValidateUrl:
    def test_valid_https(self) -> None:
        assert validate_url("https://example.com/path") == "https://example.com/path"

    def test_http_disallowed(self) -> None:
        with pytest.raises(ValueError, match="Insecure"):
            validate_url("http://example.com")

    def test_http_localhost_allowed(self) -> None:
        # localhost is permitted over http without the allow_http flag.
        assert validate_url("http://localhost:8080") == "http://localhost:8080"

    def test_http_127_allowed(self) -> None:
        assert validate_url("http://127.0.0.1:3000") == "http://127.0.0.1:3000"

    def test_invalid_url(self) -> None:
        with pytest.raises(ValueError, match="Invalid URL"):
            validate_url("not-a-url")

    def test_empty_url(self) -> None:
        with pytest.raises(ValueError, match="Invalid URL"):
            validate_url("")

    def test_url_with_path(self) -> None:
        assert validate_url("https://api.example.com/v1/payments") == (
            "https://api.example.com/v1/payments"
        )

    def test_allow_http_any_host(self) -> None:
        assert validate_url("http://pay.aws.amazon.com", allow_http=True) == (
            "http://pay.aws.amazon.com"
        )

    def test_unsupported_scheme(self) -> None:
        with pytest.raises(ValueError, match="Unsupported"):
            validate_url("ftp://example.com")
