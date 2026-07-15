# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for fiat_extension_x402.discovery module."""

from __future__ import annotations
from typing import Any


import httpx
import pytest
import respx

from fiat_extension_x402.discovery import (
    AgentPayDiscoveryMetadata,
    clear_discovery_cache,
    clear_jwks_cache,
    clear_network_registry,
    discover_agent_pay_endpoints,
    fetch_agent_pay_public_keys,
    get_agent_pay_base_url,
    get_registered_networks,
    register_network,
    unregister_network,
)
from fiat_extension_x402.exceptions import ValidationError


@pytest.fixture(autouse=True)
def _clean_registry() -> None:
    """Clear global state before each test."""
    clear_network_registry()
    clear_discovery_cache()
    clear_jwks_cache()


class TestRegisterNetwork:
    def test_register_valid_network(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        assert get_registered_networks() == {"aws:base": "https://pay.aws.amazon.com"}

    def test_register_invalid_format_no_colon(self) -> None:
        with pytest.raises(ValidationError, match="Invalid network identifier format"):
            register_network("awsbase", "https://pay.aws.amazon.com")

    def test_register_invalid_format_too_many_colons(self) -> None:
        with pytest.raises(ValidationError, match="Invalid network identifier format"):
            register_network("a:b:c", "https://pay.aws.amazon.com")

    def test_register_empty_provider(self) -> None:
        with pytest.raises(ValidationError, match="Missing provider"):
            register_network("aws:", "https://pay.aws.amazon.com")

    def test_register_invalid_url(self) -> None:
        with pytest.raises(ValidationError, match="Invalid base URL"):
            register_network("aws:base", "not-a-url")

    def test_register_multiple(self) -> None:
        register_network("fab:aws", "https://pay.aws.amazon.com")
        register_network("fab:google", "https://pay.google.com")
        register_network("custom:provider", "https://custom-pay.example.com")
        assert get_agent_pay_base_url("fab:aws") == "https://pay.aws.amazon.com"
        assert get_agent_pay_base_url("fab:google") == "https://pay.google.com"
        assert get_agent_pay_base_url("custom:provider") == "https://custom-pay.example.com"

    def test_overwrite_existing(self) -> None:
        register_network("fab:aws", "https://pay.aws.amazon.com")
        register_network("fab:aws", "https://new-pay.aws.com")
        assert get_agent_pay_base_url("fab:aws") == "https://new-pay.aws.com"

    def test_accept_any_scheme(self) -> None:
        register_network("evm:aws", "https://pay.example.com")
        assert get_agent_pay_base_url("evm:aws") == "https://pay.example.com"

    def test_reject_empty_network(self) -> None:
        with pytest.raises(ValidationError):
            register_network("", "https://pay.example.com")

    def test_reject_empty_base_url(self) -> None:
        with pytest.raises(ValidationError, match="Invalid base URL"):
            register_network("fab:test", "")

    def test_reject_url_without_protocol(self) -> None:
        with pytest.raises(ValidationError, match="Invalid base URL"):
            register_network("fab:test", "invalid-url")


class TestNetworkRegistryUrlHandling:
    """The registry preserves base URLs verbatim across URL shapes."""

    def test_preserves_trailing_slash(self) -> None:
        register_network("fab:test", "https://pay.test.com/")
        assert get_agent_pay_base_url("fab:test") == "https://pay.test.com/"

    def test_url_with_port(self) -> None:
        register_network("fab:local", "http://localhost:3000")
        assert get_agent_pay_base_url("fab:local") == "http://localhost:3000"

    def test_url_with_path(self) -> None:
        register_network("custom:provider", "https://api.example.com/pay")
        assert get_agent_pay_base_url("custom:provider") == "https://api.example.com/pay"

    def test_accepts_http_and_https(self) -> None:
        register_network("fab:http", "http://pay.test.com")
        register_network("fab:https", "https://pay.test.com")
        assert get_agent_pay_base_url("fab:http") == "http://pay.test.com"
        assert get_agent_pay_base_url("fab:https") == "https://pay.test.com"


class TestUnregisterNetwork:
    def test_unregister_existing(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        assert unregister_network("aws:base") is True
        assert get_registered_networks() == {}

    def test_unregister_nonexistent(self) -> None:
        assert unregister_network("aws:base") is False


class TestGetRegisteredNetworks:
    def test_returns_copy(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        networks = get_registered_networks()
        networks["custom:net"] = "https://example.com"
        assert "custom:net" not in get_registered_networks()

    def test_get_all(self) -> None:
        register_network("fab:aws", "https://pay.aws.amazon.com")
        register_network("fab:google", "https://pay.google.com")
        networks = get_registered_networks()
        assert len(networks) == 2
        assert networks["fab:aws"] == "https://pay.aws.amazon.com"
        assert networks["fab:google"] == "https://pay.google.com"

    def test_returns_distinct_objects(self) -> None:
        register_network("fab:aws", "https://pay.aws.amazon.com")
        networks1 = get_registered_networks()
        networks2 = get_registered_networks()
        assert networks1 is not networks2
        assert len(networks1) == len(networks2)


class TestClearNetworkRegistry:
    def test_clear(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        register_network("eip155:8453", "https://other.com")
        clear_network_registry()
        assert get_registered_networks() == {}


class TestGetAgentPayBaseUrl:
    def test_valid_registered(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        assert get_agent_pay_base_url("aws:base") == "https://pay.aws.amazon.com"

    def test_invalid_format(self) -> None:
        with pytest.raises(ValidationError, match="Invalid network identifier format"):
            get_agent_pay_base_url("nocolon")

    def test_empty_provider(self) -> None:
        with pytest.raises(ValidationError, match="Missing provider"):
            get_agent_pay_base_url("aws:")

    def test_not_registered(self) -> None:
        with pytest.raises(ValidationError, match="Network not registered"):
            get_agent_pay_base_url("aws:base")

    def test_not_registered_any_scheme(self) -> None:
        with pytest.raises(ValidationError, match="Network not registered"):
            get_agent_pay_base_url("evm:aws")


class TestDiscoverAgentPayEndpoints:
    @respx.mock
    def test_successful_discovery(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        metadata_response = {
            "issuer": "https://pay.aws.amazon.com",
            "jwks_uri": "https://pay.aws.amazon.com/.well-known/jwks.json",
            "payment_endpoint": "https://pay.aws.amazon.com/v1/payments",
            "supported_settlement_methods": ["INST"],
            "signing_alg_values_supported": ["ES384"],
        }
        respx.get("https://pay.aws.amazon.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=metadata_response)
        )

        result = discover_agent_pay_endpoints("aws:base")
        assert isinstance(result, AgentPayDiscoveryMetadata)
        assert result.issuer == "https://pay.aws.amazon.com"
        assert result.jwks_uri == "https://pay.aws.amazon.com/.well-known/jwks.json"
        assert result.payment_endpoint == "https://pay.aws.amazon.com/v1/payments"
        assert result.supported_settlement_methods == ["INST"]
        assert result.signing_alg_values_supported == ["ES384"]

    @respx.mock
    def test_caches_response(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        metadata_response = {
            "issuer": "https://pay.aws.amazon.com",
            "jwks_uri": "https://pay.aws.amazon.com/.well-known/jwks.json",
            "payment_endpoint": "https://pay.aws.amazon.com/v1/payments",
        }
        route = respx.get("https://pay.aws.amazon.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=metadata_response)
        )

        discover_agent_pay_endpoints("aws:base")
        discover_agent_pay_endpoints("aws:base")  # Should hit cache.
        assert route.call_count == 1

    @respx.mock
    def test_skip_cache(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        metadata_response = {
            "issuer": "https://pay.aws.amazon.com",
            "jwks_uri": "https://pay.aws.amazon.com/.well-known/jwks.json",
            "payment_endpoint": "https://pay.aws.amazon.com/v1/payments",
        }
        route = respx.get("https://pay.aws.amazon.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=metadata_response)
        )

        discover_agent_pay_endpoints("aws:base")
        discover_agent_pay_endpoints("aws:base", skip_cache=True)
        assert route.call_count == 2

    @respx.mock
    def test_http_error(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        respx.get("https://pay.aws.amazon.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        with pytest.raises(ValidationError, match="Failed to discover"):
            discover_agent_pay_endpoints("aws:base")

    @respx.mock
    def test_missing_required_fields(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        respx.get("https://pay.aws.amazon.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json={"issuer": "x"})
        )

        with pytest.raises(ValidationError, match="missing required fields"):
            discover_agent_pay_endpoints("aws:base")


class TestFetchAgentPayPublicKeys:
    @respx.mock
    def test_successful_fetch(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        metadata_response = {
            "issuer": "https://pay.aws.amazon.com",
            "jwks_uri": "https://pay.aws.amazon.com/.well-known/jwks.json",
            "payment_endpoint": "https://pay.aws.amazon.com/v1/payments",
        }
        jwks_response = {"keys": [{"kty": "EC", "kid": "key-1"}]}

        respx.get("https://pay.aws.amazon.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=metadata_response)
        )
        respx.get("https://pay.aws.amazon.com/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks_response)
        )

        result = fetch_agent_pay_public_keys("aws:base")
        assert result == {"keys": [{"kty": "EC", "kid": "key-1"}]}

    @respx.mock
    def test_caches_jwks(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        metadata_response = {
            "issuer": "https://pay.aws.amazon.com",
            "jwks_uri": "https://pay.aws.amazon.com/.well-known/jwks.json",
            "payment_endpoint": "https://pay.aws.amazon.com/v1/payments",
        }
        jwks_response: dict[str, list[Any]] = {"keys": []}

        respx.get("https://pay.aws.amazon.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=metadata_response)
        )
        jwks_route = respx.get("https://pay.aws.amazon.com/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks_response)
        )

        fetch_agent_pay_public_keys("aws:base")
        fetch_agent_pay_public_keys("aws:base")
        assert jwks_route.call_count == 1

    @respx.mock
    def test_respects_cache_control(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        metadata_response = {
            "issuer": "https://pay.aws.amazon.com",
            "jwks_uri": "https://pay.aws.amazon.com/.well-known/jwks.json",
            "payment_endpoint": "https://pay.aws.amazon.com/v1/payments",
        }
        jwks_response: dict[str, list[Any]] = {"keys": []}

        respx.get("https://pay.aws.amazon.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=metadata_response)
        )
        respx.get("https://pay.aws.amazon.com/.well-known/jwks.json").mock(
            return_value=httpx.Response(
                200, json=jwks_response, headers={"cache-control": "max-age=7200"}
            )
        )

        fetch_agent_pay_public_keys("aws:base")
        # Just verify it doesn't error — the cache is set.

    @respx.mock
    def test_jwks_fetch_error(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        metadata_response = {
            "issuer": "https://pay.aws.amazon.com",
            "jwks_uri": "https://pay.aws.amazon.com/.well-known/jwks.json",
            "payment_endpoint": "https://pay.aws.amazon.com/v1/payments",
        }

        respx.get("https://pay.aws.amazon.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=metadata_response)
        )
        respx.get("https://pay.aws.amazon.com/.well-known/jwks.json").mock(
            return_value=httpx.Response(403, text="Forbidden")
        )

        with pytest.raises(ValidationError, match="Failed to fetch"):
            fetch_agent_pay_public_keys("aws:base")


class TestClearCaches:
    @respx.mock
    def test_clear_discovery_cache_specific(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        metadata_response = {
            "issuer": "https://pay.aws.amazon.com",
            "jwks_uri": "https://pay.aws.amazon.com/.well-known/jwks.json",
            "payment_endpoint": "https://pay.aws.amazon.com/v1/payments",
        }
        route = respx.get("https://pay.aws.amazon.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=metadata_response)
        )

        discover_agent_pay_endpoints("aws:base")
        clear_discovery_cache("aws:base")
        discover_agent_pay_endpoints("aws:base")
        assert route.call_count == 2

    @respx.mock
    def test_clear_jwks_cache_specific(self) -> None:
        register_network("aws:base", "https://pay.aws.amazon.com")
        metadata_response = {
            "issuer": "https://pay.aws.amazon.com",
            "jwks_uri": "https://pay.aws.amazon.com/.well-known/jwks.json",
            "payment_endpoint": "https://pay.aws.amazon.com/v1/payments",
        }
        jwks_response: dict[str, list[Any]] = {"keys": []}

        respx.get("https://pay.aws.amazon.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=metadata_response)
        )
        jwks_route = respx.get("https://pay.aws.amazon.com/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=jwks_response)
        )

        fetch_agent_pay_public_keys("aws:base")
        assert jwks_route.call_count == 1

        clear_jwks_cache("https://pay.aws.amazon.com/.well-known/jwks.json")
        fetch_agent_pay_public_keys("aws:base")
        assert jwks_route.call_count == 2

    @respx.mock
    def test_clear_jwks_cache_all(self) -> None:
        clear_jwks_cache()  # Should not raise.


class TestClearDiscoveryCacheIdempotent:
    """clear_discovery_cache is safe to call repeatedly with no entries."""

    def test_clear_without_error(self) -> None:
        clear_discovery_cache()  # Should not raise.

    def test_idempotent(self) -> None:
        clear_discovery_cache()
        clear_discovery_cache()
        clear_discovery_cache()  # Should not raise.
