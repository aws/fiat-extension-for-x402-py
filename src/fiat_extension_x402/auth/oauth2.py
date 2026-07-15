# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""OAuth 2.0 Bearer token authentication strategy."""

from __future__ import annotations

import threading
from typing import Callable, Optional

from fiat_extension_x402.auth.errors import InvalidCredentialsError
from fiat_extension_x402.auth.types import SignedRequest


class OAuth2Authenticator:
    """Authenticates requests using an OAuth 2.0 Bearer token.

    :param access_token: The initial access token.
    :param on_refresh: Optional callback to obtain a fresh token.
    :raises InvalidCredentialsError: if ``access_token`` is empty.
    """

    def __init__(
        self,
        access_token: str,
        *,
        on_refresh: Optional[Callable[[], str]] = None,
    ) -> None:
        if not access_token:
            raise InvalidCredentialsError("oauth2", "accessToken must not be empty")
        self._access_token = access_token
        self._on_refresh = on_refresh
        self._lock = threading.Lock()
        self._refreshing = False

    def authenticate(self, request: SignedRequest) -> SignedRequest:
        """Return a copy of ``request`` with the Bearer authorization header added."""
        # Wait if another thread is refreshing.
        with self._lock:
            token = self._access_token
        headers = {**request.headers, "Authorization": f"Bearer {token}"}
        return SignedRequest(
            url=request.url,
            method=request.method,
            headers=headers,
            body=request.body,
        )

    def refresh_access_token(self) -> None:
        """Refresh the access token using the ``on_refresh`` callback.

        Prevents concurrent refreshes — only one caller proceeds; others wait.
        """
        if self._on_refresh is None:
            return
        with self._lock:
            if self._refreshing:
                return
            self._refreshing = True
        try:
            new_token = self._on_refresh()
            with self._lock:
                self._access_token = new_token
        finally:
            with self._lock:
                self._refreshing = False

    def get_access_token(self) -> str:
        """Return the current access token."""
        with self._lock:
            return self._access_token


__all__ = ["OAuth2Authenticator"]
