# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Public security utilities for token verification."""

from __future__ import annotations

import hmac

# Algorithms accepted for JWT signature verification.
ALLOWED_ALGORITHMS: list[str] = ["RS256", "ES256", "ES384", "ES512"]


def secure_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks.

    :param a: First string.
    :param b: Second string.
    :returns: ``True`` if the strings are equal, ``False`` otherwise.
    """
    return hmac.compare_digest(a.encode(), b.encode())


__all__ = [
    "ALLOWED_ALGORITHMS",
    "secure_compare",
]
