# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Agent Pay server scheme — quote token generation and payment requirements enhancement.

In Agent Pay, the "server" role is played by the resource service, which
generates HTTP 402 responses with signed quote tokens.
"""

from __future__ import annotations

import uuid
from time import time
from typing import Any

from fiat_extension_x402.constants import (
    AGENT_PAY_AUDIENCE,
    AGENT_PAY_SENTINEL_PAY_TO,
    DEFAULT_QUOTE_VALIDITY_SECONDS,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.signers.protocol import ServiceAgentPaySigner


async def enhance_payment_requirements(
    payment_requirements: dict[str, Any],
    signer: ServiceAgentPaySigner,
) -> dict[str, Any]:
    """Enhance payment requirements with a signed quote token.

    Constructs the quote token claims from the base payment requirements,
    signs it via the provided :class:`ServiceAgentPaySigner`, and returns
    enhanced payment requirements with the signed quote token in the
    ``extra.quoteToken`` field.

    Sentinel values replace fields that are redundant in Agent Pay — the
    signed quote token is the authoritative source for payment recipient
    (``payTo``) and validity window (``exp - iat``).

    :param payment_requirements: Base x402 payment requirements dict.
    :param signer: A signer satisfying the :class:`ServiceAgentPaySigner` protocol.
    :returns: Enhanced payment requirements dict with the quote token.
    """
    amount = payment_requirements["amount"]
    currency = payment_requirements.get("asset", "").replace("iso4217:", "")

    extra: dict[str, Any] = dict(payment_requirements.get("extra") or {})

    # The ``iss`` claim identifies the issuing service and is required by the
    # Agent Pay service — an empty issuer is rejected with a 400. Validate here
    # so no signer type can ever produce a quote token with an empty ``iss``.
    issuer = signer.get_service_url()
    if not issuer or not issuer.strip():
        raise ValidationError(
            "Cannot sign quote token: signer service URL (issuer) is empty. "
            "Configure a non-empty service_url on the signer — it becomes the "
            "quote token's 'iss' claim, which Agent Pay requires."
        )

    now = int(time())
    max_timeout = payment_requirements.get("maxTimeoutSeconds") or DEFAULT_QUOTE_VALIDITY_SECONDS

    quote_payload: dict[str, Any] = {
        "iss": issuer,
        "aud": AGENT_PAY_AUDIENCE,
        "iat": now,
        "exp": now + max_timeout,
        "jti": str(uuid.uuid4()),
        "price": {
            "amount": amount,
            "currency": currency,
        },
        "payTo": payment_requirements["payTo"],
        "reference": extra.get("reference") or "RESOURCE",
    }

    # Include optional claims only when present in the input.
    if extra.get("description") is not None:
        quote_payload["description"] = extra["description"]
    if extra.get("dimensions") is not None:
        quote_payload["dimensions"] = extra["dimensions"]
    if extra.get("settlement") is not None:
        quote_payload["settlement"] = extra["settlement"]
    if extra.get("support") is not None:
        quote_payload["support"] = extra["support"]
    if extra.get("terms") is not None:
        quote_payload["terms"] = extra["terms"]

    # Sign quote token.
    quote_token = await signer.sign_quote(quote_payload)

    # Add quote token to extra.
    extra["quoteToken"] = quote_token

    # Return enhanced requirements with sentinel values for fields that are
    # redundant in Agent Pay.
    return {
        **payment_requirements,
        "payTo": AGENT_PAY_SENTINEL_PAY_TO,
        "maxTimeoutSeconds": quote_payload["exp"] - quote_payload["iat"],
        "extra": extra,
    }


__all__ = ["enhance_payment_requirements"]
