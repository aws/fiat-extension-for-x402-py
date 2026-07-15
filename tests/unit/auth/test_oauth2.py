# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for OAuth2 authenticator."""

from __future__ import annotations

import pytest

from fiat_extension_x402.auth import OAuth2Authenticator, SignedRequest
from fiat_extension_x402.auth.errors import InvalidCredentialsError


class TestOAuth2Authenticator:
    def test_basic(self) -> None:
        auth = OAuth2Authenticator("token123")
        req = SignedRequest(url="https://example.com", method="GET", headers={})
        result = auth.authenticate(req)
        assert result.headers["Authorization"] == "Bearer token123"

    def test_empty_token_raises(self) -> None:
        with pytest.raises(InvalidCredentialsError):
            OAuth2Authenticator("")

    def test_get_access_token(self) -> None:
        auth = OAuth2Authenticator("initial")
        assert auth.get_access_token() == "initial"

    def test_refresh(self) -> None:
        auth = OAuth2Authenticator("old", on_refresh=lambda: "new")
        auth.refresh_access_token()
        assert auth.get_access_token() == "new"


class TestOAuth2RefreshPaths:
    """Cover the refresh paths in OAuth2Authenticator."""

    def test_refresh_no_callback_is_noop(self) -> None:
        """refresh_access_token with no on_refresh is a no-op (returns immediately)."""
        auth = OAuth2Authenticator("tok")
        auth.refresh_access_token()  # Should not raise
        assert auth.get_access_token() == "tok"

    def test_refresh_with_callback(self) -> None:
        """refresh_access_token with callback updates the token."""
        auth = OAuth2Authenticator("old", on_refresh=lambda: "new-token")
        auth.refresh_access_token()
        assert auth.get_access_token() == "new-token"

    def test_refresh_dedup_flag(self) -> None:
        """Cover the _refreshing guard path (line 56-57)."""
        # Directly set _refreshing to simulate concurrent access
        auth = OAuth2Authenticator("init", on_refresh=lambda: "new")
        # Simulate another thread already refreshing
        auth._refreshing = True  # noqa: SLF001 - testing internal state
        auth.refresh_access_token()  # Should return immediately (line 57)
        # Token unchanged because refresh was skipped
        assert auth.get_access_token() == "init"
        # Reset and actually refresh
        auth._refreshing = False  # noqa: SLF001
        auth.refresh_access_token()
        assert auth.get_access_token() == "new"
