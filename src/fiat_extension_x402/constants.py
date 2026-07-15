# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Constants for the Agent Pay x402 extension."""

from __future__ import annotations

# Agent Pay scheme identifier.
AGENT_PAY_SCHEME = "agent-pay"

# Default quote token validity (5 minutes).
DEFAULT_QUOTE_VALIDITY_SECONDS = 300

# Default payment token validity (1 hour).
DEFAULT_PAYMENT_VALIDITY_SECONDS = 3600

# Default network identifier for AWS Marketplace Agent Pay.
DEFAULT_NETWORK = "aws:base"

# Payment JWT issuer claim value used by the AWS Marketplace Agent Pay Service.
PAYMENT_JWT_ISSUER = "awsmp-agentpay.amazonaws.com"

# Sentinel value for PaymentRequirements.payTo in Agent Pay.
#
# In Agent Pay, the signed quote token is the authoritative source for the payment
# recipient. The outer PaymentRequirements.payTo field is required by x402 core
# but semantically redundant — the quote token's payTo is signed by the service
# and cannot be tampered with, whereas the outer field is unsigned.
AGENT_PAY_SENTINEL_PAY_TO = "urn:x402:agent-pay:see-quote"

# Path to the JWKS endpoint for public key discovery.
WELL_KNOWN_JWKS_PATH = "/.well-known/jwks.json"

# Path to the x402 supported kinds endpoint.
WELL_KNOWN_X402_SUPPORTED_PATH = "/.well-known/x402-supported"

# Path to the OIDC discovery endpoint.
WELL_KNOWN_OIDC_PATH = "/.well-known/openid-configuration"

# The audience identifier for the AWS Marketplace Agent Pay Service.
# This is the ``aud`` claim in quote tokens — it identifies WHO processes the token.
AGENT_PAY_AUDIENCE = "aws:marketplace"

# Default base URL for Agent Pay's JWKS (signing key) endpoint.
AGENT_PAY_JWKS_BASE_URL = "https://d3aeb2cjjowogc.cloudfront.net"

# WAF access header value required to fetch Agent Pay's JWKS endpoint.
AGENT_PAY_JWKS_ACCESS_KEY = "agentpay-test-2026"

# Default base URL for the Agent Pay service endpoint.
DEFAULT_AGENT_PAY_BASE_URL = "https://prod.agentpay.marketplace.aws.dev"

# CAIP-2 family identifier for AWS Agent Pay networks.
AGENT_PAY_CAIP_FAMILY = "aws:*"

# Valid settlement methods (ISO 20022-derived codes).
SETTLEMENT_METHODS: dict[str, str] = {
    "INST": "INST",
    "CLRG": "CLRG",
    "CRDT": "CRDT",
}

# Valid settlement cycles.
SETTLEMENT_CYCLES: dict[str, str] = {
    "MNTH": "MNTH",
    "WEEK": "WEEK",
    "QRTR": "QRTR",
}

__all__ = [
    "AGENT_PAY_AUDIENCE",
    "AGENT_PAY_CAIP_FAMILY",
    "AGENT_PAY_JWKS_ACCESS_KEY",
    "AGENT_PAY_JWKS_BASE_URL",
    "AGENT_PAY_SCHEME",
    "AGENT_PAY_SENTINEL_PAY_TO",
    "DEFAULT_AGENT_PAY_BASE_URL",
    "DEFAULT_NETWORK",
    "DEFAULT_PAYMENT_VALIDITY_SECONDS",
    "DEFAULT_QUOTE_VALIDITY_SECONDS",
    "PAYMENT_JWT_ISSUER",
    "SETTLEMENT_CYCLES",
    "SETTLEMENT_METHODS",
    "WELL_KNOWN_JWKS_PATH",
    "WELL_KNOWN_OIDC_PATH",
    "WELL_KNOWN_X402_SUPPORTED_PATH",
]
