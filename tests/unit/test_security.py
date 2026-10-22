# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for security module."""

from __future__ import annotations

from fiat_extension_x402.security import ALLOWED_ALGORITHMS, secure_compare


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
