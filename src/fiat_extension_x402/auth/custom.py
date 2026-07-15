# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Custom authentication strategy with user-supplied callable."""

from __future__ import annotations

from typing import Callable

from fiat_extension_x402.auth.errors import InvalidCredentialsError
from fiat_extension_x402.auth.types import SignedRequest


class CustomAuthenticator:
    """Authenticates requests via a user-supplied callable.

    The callable receives a :class:`SignedRequest` and must return a
    :class:`SignedRequest` with ``url``, ``method``, and ``headers`` set.

    :param authenticate_fn: Callable that transforms the request.
    :raises InvalidCredentialsError: if ``authenticate_fn`` is not callable.
    """

    def __init__(self, authenticate_fn: Callable[[SignedRequest], SignedRequest]) -> None:
        if not callable(authenticate_fn):
            raise InvalidCredentialsError("custom", "authenticate must be callable")
        self._authenticate_fn = authenticate_fn

    def authenticate(self, request: SignedRequest) -> SignedRequest:
        """Delegate to the user-supplied callable and validate the result."""
        result = self._authenticate_fn(request)
        if (
            not hasattr(result, "url")
            or not hasattr(result, "method")
            or not hasattr(result, "headers")
        ):
            raise InvalidCredentialsError(
                "custom", "authenticate must return an object with url, method, and headers"
            )
        return result


__all__ = ["CustomAuthenticator"]
