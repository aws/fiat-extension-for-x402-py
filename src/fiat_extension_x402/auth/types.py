# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Authentication types for client-to-Agent-Pay communication."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol


@dataclass
class SignedRequest:
    """An HTTP request passed through an :class:`Authenticator`.

    An authenticator returns a new :class:`SignedRequest` with the headers needed
    to authenticate the request (e.g. SigV4 ``Authorization`` and ``x-amz-*``).
    """

    url: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None


class Authenticator(Protocol):
    """Attaches authentication headers to an outgoing request."""

    def authenticate(self, request: SignedRequest) -> SignedRequest:
        """Return a copy of ``request`` with authentication headers added."""
        ...


__all__ = ["Authenticator", "SignedRequest"]
