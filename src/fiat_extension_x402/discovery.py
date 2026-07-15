# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Agent Pay endpoint discovery via OIDC discovery.

Utilities for discovering Agent Pay provider endpoints, managing a network
registry, and caching discovery metadata and JWKS responses.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from fiat_extension_x402.constants import WELL_KNOWN_OIDC_PATH
from fiat_extension_x402.exceptions import ValidationError


@dataclass(frozen=True)
class AgentPayDiscoveryMetadata:
    """Agent Pay discovery metadata (OIDC Discovery response).

    :param issuer: Agent Pay's canonical identifier (matches ``iss`` in Payment JWTs).
    :param jwks_uri: URL where services can fetch Agent Pay's public keys.
    :param payment_endpoint: URL where clients create payment transactions.
    :param supported_settlement_methods: Settlement methods this provider supports.
    :param signing_alg_values_supported: Algorithms used to sign Payment JWTs.
    :param dpop_signing_alg_values_supported: Algorithms supported for DPoP proof JWTs.
    :param token_endpoint_auth_methods_supported: Authentication methods accepted.
    :param grant_types_supported: Grant types supported.
    """

    issuer: str
    jwks_uri: str
    payment_endpoint: str
    supported_settlement_methods: Optional[list[str]] = None
    signing_alg_values_supported: Optional[list[str]] = None
    dpop_signing_alg_values_supported: Optional[list[str]] = None
    token_endpoint_auth_methods_supported: Optional[list[str]] = None
    grant_types_supported: Optional[list[str]] = None


@dataclass
class _CacheEntry:
    """Internal cache entry with TTL."""

    data: Any
    expires_at: float


# Module-level registries and caches.
_network_registry: dict[str, str] = {}
_discovery_cache: dict[str, _CacheEntry] = {}
_jwks_cache: dict[str, _CacheEntry] = {}

# Cache durations.
_DISCOVERY_CACHE_TTL_MS = 24 * 60 * 60 * 1000  # 24 hours
_JWKS_CACHE_TTL_MS = 60 * 60 * 1000  # 1 hour default


def register_network(network: str, base_url: str) -> None:
    """Register a network's Agent Pay base URL.

    :param network: Network identifier (e.g., ``'aws:base'``).
    :param base_url: Agent Pay base URL (e.g., ``'https://pay.aws.amazon.com'``).
    :raises ValidationError: if network format or base URL is invalid.
    """
    parts = network.split(":")
    if len(parts) != 2:
        raise ValidationError(f"Invalid network identifier format: {network}")

    _scheme, provider = parts
    if not provider or provider.strip() == "":
        raise ValidationError(f"Missing provider in network identifier: {network}")

    # Validate base URL.
    try:
        parsed = httpx.URL(base_url)
        if not parsed.scheme or not parsed.host:
            raise ValueError("missing scheme or host")
    except Exception:
        raise ValidationError(f"Invalid base URL: {base_url}")

    _network_registry[network] = base_url


def unregister_network(network: str) -> bool:
    """Unregister a network.

    :param network: Network identifier to unregister.
    :returns: ``True`` if the network was unregistered, ``False`` if it was not found.
    """
    return _network_registry.pop(network, None) is not None


def get_registered_networks() -> dict[str, str]:
    """Get all registered networks.

    :returns: Copy of the network registry mapping identifiers to base URLs.
    """
    return dict(_network_registry)


def clear_network_registry() -> None:
    """Clear all registered networks."""
    _network_registry.clear()


def get_agent_pay_base_url(network: str) -> str:
    """Get Agent Pay base URL from the network registry.

    :param network: Network identifier (e.g., ``'aws:base'``).
    :returns: Agent Pay base URL.
    :raises ValidationError: if the network format is invalid or not registered.
    """
    parts = network.split(":")
    if len(parts) < 2:
        raise ValidationError(f"Invalid network identifier format: {network}")

    provider = ":".join(parts[1:])
    if not provider or provider.strip() == "":
        raise ValidationError(f"Missing provider in network identifier: {network}")

    base_url = _network_registry.get(network)
    if not base_url:
        raise ValidationError(
            f"Network not registered: {network}. Use register_network() to register it."
        )

    return base_url


def discover_agent_pay_endpoints(
    network: str,
    *,
    skip_cache: bool = False,
) -> AgentPayDiscoveryMetadata:
    """Discover Agent Pay endpoints via OIDC discovery.

    Fetches the Agent Pay's OIDC discovery document to get endpoint URLs and
    supported capabilities.

    :param network: Network identifier (e.g., ``'aws:base'``).
    :param skip_cache: Skip cache and force a fresh fetch.
    :returns: Agent Pay discovery metadata.
    :raises ValidationError: if the fetch fails or response is invalid.
    """
    now_ms = time.time() * 1000

    # Check cache.
    if not skip_cache:
        cached = _discovery_cache.get(network)
        if cached and cached.expires_at > now_ms:
            result: AgentPayDiscoveryMetadata = cached.data
            return result

    # Fetch discovery document.
    base_url = get_agent_pay_base_url(network)
    discovery_url = f"{base_url}{WELL_KNOWN_OIDC_PATH}"

    with httpx.Client() as client:
        response = client.get(discovery_url)

    if not (200 <= response.status_code < 300):
        raise ValidationError(
            f"Failed to discover Agent Pay endpoints for {network}: "
            f"{response.status_code} {response.reason_phrase}"
        )

    data = response.json()

    # Validate required fields.
    if not data.get("issuer") or not data.get("jwks_uri") or not data.get("payment_endpoint"):
        raise ValidationError(f"Invalid discovery metadata for {network}: missing required fields")

    metadata = AgentPayDiscoveryMetadata(
        issuer=data["issuer"],
        jwks_uri=data["jwks_uri"],
        payment_endpoint=data["payment_endpoint"],
        supported_settlement_methods=data.get("supported_settlement_methods"),
        signing_alg_values_supported=data.get("signing_alg_values_supported"),
        dpop_signing_alg_values_supported=data.get("dpop_signing_alg_values_supported"),
        token_endpoint_auth_methods_supported=data.get("token_endpoint_auth_methods_supported"),
        grant_types_supported=data.get("grant_types_supported"),
    )

    # Cache for 24 hours.
    _discovery_cache[network] = _CacheEntry(
        data=metadata,
        expires_at=now_ms + _DISCOVERY_CACHE_TTL_MS,
    )

    return metadata


def fetch_agent_pay_public_keys(
    network: str,
    *,
    skip_cache: bool = False,
) -> Any:
    """Fetch Agent Pay's public keys (JWKS) for signature verification.

    :param network: Network identifier (e.g., ``'aws:base'``).
    :param skip_cache: Skip cache and force a fresh fetch.
    :returns: JSON Web Key Set (dict).
    :raises ValidationError: if the fetch fails.
    """
    # Get JWKS URI from discovery.
    metadata = discover_agent_pay_endpoints(network, skip_cache=skip_cache)
    jwks_uri = metadata.jwks_uri

    now_ms = time.time() * 1000

    # Check cache.
    if not skip_cache:
        cached = _jwks_cache.get(jwks_uri)
        if cached and cached.expires_at > now_ms:
            return cached.data

    # Fetch JWKS.
    with httpx.Client() as client:
        response = client.get(jwks_uri)

    if not (200 <= response.status_code < 300):
        raise ValidationError(
            f"Failed to fetch Agent Pay public keys from {jwks_uri}: "
            f"{response.status_code} {response.reason_phrase}"
        )

    jwks = response.json()

    # Cache duration: use Cache-Control max-age if present, otherwise 1 hour.
    cache_duration_ms = _JWKS_CACHE_TTL_MS
    cache_control = response.headers.get("cache-control", "")
    max_age_match = re.search(r"max-age=(\d+)", cache_control)
    if max_age_match:
        cache_duration_ms = int(max_age_match.group(1)) * 1000

    _jwks_cache[jwks_uri] = _CacheEntry(
        data=jwks,
        expires_at=now_ms + cache_duration_ms,
    )

    return jwks


def clear_discovery_cache(network: Optional[str] = None) -> None:
    """Clear discovery cache.

    :param network: Optional network identifier to clear a specific entry.
        If ``None``, clears all entries.
    """
    if network:
        _discovery_cache.pop(network, None)
    else:
        _discovery_cache.clear()


def clear_jwks_cache(jwks_uri: Optional[str] = None) -> None:
    """Clear JWKS cache.

    :param jwks_uri: Optional JWKS URI to clear a specific entry.
        If ``None``, clears all entries.
    """
    if jwks_uri:
        _jwks_cache.pop(jwks_uri, None)
    else:
        _jwks_cache.clear()


__all__ = [
    "AgentPayDiscoveryMetadata",
    "clear_discovery_cache",
    "clear_jwks_cache",
    "clear_network_registry",
    "discover_agent_pay_endpoints",
    "fetch_agent_pay_public_keys",
    "get_agent_pay_base_url",
    "get_registered_networks",
    "register_network",
    "unregister_network",
]
