# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for API key authenticator."""

from __future__ import annotations

import pytest

from fiat_extension_x402.auth import ApiKeyAuthenticator, SignedRequest
from fiat_extension_x402.auth.errors import InvalidCredentialsError


class TestApiKeyAuthenticator:
    def test_basic(self) -> None:
        auth = ApiKeyAuthenticator("my-key")
        req = SignedRequest(url="https://example.com", method="GET", headers={})
        result = auth.authenticate(req)
        assert result.headers["X-API-Key"] == "my-key"

    def test_custom_header(self) -> None:
        auth = ApiKeyAuthenticator("k", header_name="Authorization")
        req = SignedRequest(url="https://example.com", method="GET", headers={})
        result = auth.authenticate(req)
        assert result.headers["Authorization"] == "k"

    def test_prefix(self) -> None:
        auth = ApiKeyAuthenticator("key123", prefix="Bearer ")
        req = SignedRequest(url="https://example.com", method="GET", headers={})
        result = auth.authenticate(req)
        assert result.headers["X-API-Key"] == "Bearer key123"

    def test_empty_key_raises(self) -> None:
        with pytest.raises(InvalidCredentialsError):
            ApiKeyAuthenticator("")

    def test_does_not_mutate_original_request(self) -> None:
        auth = ApiKeyAuthenticator("my-key")
        req = SignedRequest(
            url="https://example.com", method="POST", headers={"Content-Type": "application/json"}
        )
        original_headers = dict(req.headers)
        auth.authenticate(req)
        assert req.headers == original_headers
        assert "X-API-Key" not in req.headers
