# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""API key authentication strategy."""

from __future__ import annotations

from typing import Optional

from fiat_extension_x402.auth.errors import InvalidCredentialsError
from fiat_extension_x402.auth.types import SignedRequest


class ApiKeyAuthenticator:
    """Authenticates requests by attaching an API key header.

    :param api_key: The API key value.
    :param header_name: HTTP header name. Defaults to ``X-API-Key``.
    :param prefix: Optional prefix prepended to the key (e.g. ``"Bearer "``).
    :raises InvalidCredentialsError: if ``api_key`` is empty.
    """

    def __init__(
        self,
        api_key: str,
        *,
        header_name: str = "X-API-Key",
        prefix: Optional[str] = None,
    ) -> None:
        if not api_key:
            raise InvalidCredentialsError("apiKey", "apiKey must not be empty")
        self._api_key = api_key
        self._header_name = header_name
        self._prefix = prefix

    def authenticate(self, request: SignedRequest) -> SignedRequest:
        """Return a copy of ``request`` with the API key header added."""
        value = f"{self._prefix}{self._api_key}" if self._prefix else self._api_key
        headers = {**request.headers, self._header_name: value}
        return SignedRequest(
            url=request.url,
            method=request.method,
            headers=headers,
            body=request.body,
        )


__all__ = ["ApiKeyAuthenticator"]
