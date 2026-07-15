# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Public security utilities for token verification and URL validation."""

from __future__ import annotations

import hmac
from urllib.parse import urlparse

# Algorithms accepted for JWT signature verification.
ALLOWED_ALGORITHMS: list[str] = ["RS256", "ES256", "ES384", "ES512"]


def secure_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks.

    :param a: First string.
    :param b: Second string.
    :returns: ``True`` if the strings are equal, ``False`` otherwise.
    """
    return hmac.compare_digest(a.encode(), b.encode())


def validate_url(url: str, allow_http: bool = False) -> str:
    """Validate a URL and enforce HTTPS.

    When ``allow_http`` is ``True``, ``http`` is permitted on any host. Otherwise
    ``http`` is permitted only on ``localhost``/``127.0.0.1`` (for local testing).

    :param url: URL string to validate.
    :param allow_http: When ``True``, allow ``http`` on any host.
    :returns: The validated URL string.
    :raises ValueError: if the URL is invalid or uses an insecure scheme.
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")

    if allow_http:
        return url

    if parsed.scheme == "https":
        return url

    if parsed.scheme == "http":
        hostname = parsed.hostname or ""
        if hostname in ("localhost", "127.0.0.1"):
            return url
        raise ValueError(
            f"Insecure URL scheme 'http' is not allowed for host '{hostname}'. "
            "Use HTTPS or set allow_http=True."
        )

    raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")


__all__ = [
    "ALLOWED_ALGORITHMS",
    "secure_compare",
    "validate_url",
]
