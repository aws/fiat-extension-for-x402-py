# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Constants for the AWS Marketplace Agentic Commerce x402 extension."""

from __future__ import annotations

# x402 scheme identifier for a fixed-price payment.
SCHEME_EXACT = "exact"

# CAIP-2 family identifier for AWS Marketplace Agentic Commerce networks.
AGENTIC_COMMERCE_CAIP_FAMILY = "aws:*"

# Default network identifier.
DEFAULT_NETWORK = "aws:base"

# Default asset: prices are fiat amounts identified by ISO 4217 currency code.
DEFAULT_ASSET = "iso4217:USD"

# Default quote token validity (5 minutes).
DEFAULT_QUOTE_VALIDITY_SECONDS = 300

# ``iss`` claim of every payment token issued by the AWS Marketplace Agentic
# Commerce service. The value is set by the service and is verified here.
PAYMENT_TOKEN_ISSUER = "awsmp-agentpay.amazonaws.com"

# ``aud`` claim of quote tokens: the service that redeems them.
QUOTE_TOKEN_AUDIENCE = "aws:marketplace"

# Sentinel ``payTo`` in payment requirements. The signed quote token is the
# authoritative source for the recipient; the outer, unsigned field is required
# by x402 core but carries no information.
SENTINEL_PAY_TO = "urn:x402:agentic-commerce:see-quote"

# Asset transfer method advertised to x402 core. It never appears on the wire.
ASSET_TRANSFER_METHOD = "payment-token"

# Requirement fields that change on every 402 and are therefore excluded when
# x402 core matches a buyer's ``accepted`` requirements against the route's.
DYNAMIC_EXTRA_FIELDS = ["quoteToken"]

# Default base URL of the service's payment-token signing keys (JWKS).
DEFAULT_PAYMENT_TOKEN_JWKS_BASE_URL = "https://agenticcommerce-marketplace.us-east-1.api.aws"

# Path to the JWKS document under a base URL.
WELL_KNOWN_JWKS_PATH = "/.well-known/jwks.json"

__all__ = [
    "AGENTIC_COMMERCE_CAIP_FAMILY",
    "ASSET_TRANSFER_METHOD",
    "DEFAULT_ASSET",
    "DEFAULT_NETWORK",
    "DEFAULT_PAYMENT_TOKEN_JWKS_BASE_URL",
    "DEFAULT_QUOTE_VALIDITY_SECONDS",
    "DYNAMIC_EXTRA_FIELDS",
    "PAYMENT_TOKEN_ISSUER",
    "QUOTE_TOKEN_AUDIENCE",
    "SCHEME_EXACT",
    "SENTINEL_PAY_TO",
    "WELL_KNOWN_JWKS_PATH",
]
