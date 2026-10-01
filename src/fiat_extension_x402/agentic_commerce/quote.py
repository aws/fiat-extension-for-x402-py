# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Quote tokens: the seller's signed statement of what a request costs."""

from __future__ import annotations

import uuid
from time import time
from typing import Any

from fiat_extension_x402.constants import (
    DEFAULT_QUOTE_VALIDITY_SECONDS,
    QUOTE_TOKEN_AUDIENCE,
    SENTINEL_PAY_TO,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.signers.protocol import QuoteSigner

# Optional route details copied from ``extra`` into the quote when present.
_OPTIONAL_QUOTE_CLAIMS = ("description", "dimensions", "settlement", "support", "terms")


def enhance_payment_requirements(
    payment_requirements: dict[str, Any],
    signer: QuoteSigner,
) -> dict[str, Any]:
    """Sign a quote token for the requirements and embed it in ``extra.quoteToken``.

    The returned requirements carry the sentinel ``payTo`` and a
    ``maxTimeoutSeconds`` equal to the quote's validity: the signed quote is the
    authoritative source for both.

    :param payment_requirements: Base x402 payment requirements (wire field names).
    :param signer: Signer for the quote token. Its service URL becomes ``iss``.
    :returns: Enhanced payment requirements.
    :raises ValidationError: if the signer's service URL is empty.
    """
    issuer = signer.get_service_url()
    if not issuer or not issuer.strip():
        raise ValidationError(
            "Cannot sign quote token: signer service URL (issuer) is empty. "
            "Configure a non-empty service_url on the signer; it becomes the quote "
            "token's 'iss' claim, which the service requires."
        )

    extra: dict[str, Any] = dict(payment_requirements.get("extra") or {})
    now = int(time())
    validity = payment_requirements.get("maxTimeoutSeconds") or DEFAULT_QUOTE_VALIDITY_SECONDS

    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": QUOTE_TOKEN_AUDIENCE,
        "iat": now,
        "exp": now + validity,
        "jti": str(uuid.uuid4()),
        "price": {
            "amount": payment_requirements["amount"],
            "currency": payment_requirements.get("asset", "").replace("iso4217:", ""),
        },
        "payTo": payment_requirements["payTo"],
        "reference": extra.get("reference") or "RESOURCE",
    }
    for name in _OPTIONAL_QUOTE_CLAIMS:
        if extra.get(name) is not None:
            claims[name] = extra[name]

    extra["quoteToken"] = signer.sign_quote(claims)
    return {
        **payment_requirements,
        "payTo": SENTINEL_PAY_TO,
        "maxTimeoutSeconds": claims["exp"] - claims["iat"],
        "extra": extra,
    }


__all__ = ["enhance_payment_requirements"]
