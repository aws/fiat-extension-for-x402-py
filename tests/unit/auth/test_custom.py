# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for custom authenticator."""

from __future__ import annotations

from typing import Any

import pytest

from fiat_extension_x402.auth import CustomAuthenticator, SignedRequest
from fiat_extension_x402.auth.errors import InvalidCredentialsError


class TestCustomAuthenticator:
    def test_basic(self) -> None:
        def my_auth(r: SignedRequest) -> SignedRequest:
            return SignedRequest(
                url=r.url, method=r.method, headers={**r.headers, "X-Custom": "val"}
            )

        auth = CustomAuthenticator(my_auth)
        req = SignedRequest(url="https://example.com", method="GET", headers={})
        result = auth.authenticate(req)
        assert result.headers["X-Custom"] == "val"

    def test_not_callable_raises(self) -> None:
        with pytest.raises(InvalidCredentialsError):
            CustomAuthenticator("not-a-function")  # type: ignore[arg-type]

    def test_can_modify_all_request_properties(self) -> None:
        def my_auth(r: SignedRequest) -> SignedRequest:
            return SignedRequest(
                url=r.url + "?authenticated=true",
                method=r.method,
                headers={**r.headers, "X-Signature": "sig-123"},
                body=r.body,
            )

        auth = CustomAuthenticator(my_auth)
        req = SignedRequest(url="https://pay.example.com/tx", method="POST", headers={}, body=b"{}")
        result = auth.authenticate(req)
        assert result.url == "https://pay.example.com/tx?authenticated=true"
        assert result.headers["X-Signature"] == "sig-123"
        assert result.body == b"{}"


class TestCustomAuthenticatorValidation:
    """Cover validation error paths in CustomAuthenticator."""

    def test_returns_invalid_result(self) -> None:
        """Custom function returning non-object raises InvalidCredentialsError."""

        def bad_auth(r: SignedRequest) -> Any:
            return "not-a-request"  # Invalid return (no url/method/headers attrs)

        auth = CustomAuthenticator(bad_auth)
        req = SignedRequest(url="https://x.com", method="GET", headers={})
        with pytest.raises(InvalidCredentialsError, match="url, method, and headers"):
            auth.authenticate(req)
