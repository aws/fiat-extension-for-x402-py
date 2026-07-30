# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for AgentPayClient.

Covers:
- Happy-path payment creation
- clientToken is sent only when provided
- SigV4 signing of outgoing requests
- Error handling: HTTP errors, 409 conflict, network and parse failures
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import pytest
import respx
from botocore.credentials import Credentials  # type: ignore[import-untyped]

from fiat_extension_x402.auth import SignedRequest
from fiat_extension_x402.client import AgentPayClient, DEFAULT_BASE_URL
from fiat_extension_x402.exceptions import IdempotencyConflictError, ValidationError
from fiat_extension_x402.schemas import CreateAgentPaymentRequest

_TEST_BASE_URL = "https://test.agentpay.example.com"
_CREATE_URL = f"{_TEST_BASE_URL}/CreateAgentPayment"

_FAKE_CREDENTIALS = Credentials(
    access_key="AKIAIOSFODNN7EXAMPLE",
    secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    token="FwoGZXIvYXdzEBYaDHqa0AP1",
)

_VALID_RESPONSE: dict[str, object] = {
    "paymentId": "awsmp-01970f3e-4b2a-7dc0-8e1f-6a3b9c5d7e2f",
    "paymentToken": "eyJhbGciOiJFUzM4NCJ9.test.signature",
    "createdAt": "2026-06-01T12:00:00Z",
}


def _make_request(
    *, quote_token: str = "eyJ...", client_token: str | None = None
) -> CreateAgentPaymentRequest:
    """Build a validated CreateAgentPaymentRequest."""
    data: dict[str, object] = {"quoteToken": quote_token}
    if client_token is not None:
        data["clientToken"] = client_token
    return CreateAgentPaymentRequest.model_validate(data)


def _make_client(base_url: str = _TEST_BASE_URL) -> AgentPayClient:
    """Create an AgentPayClient with fake credentials."""
    return AgentPayClient(base_url=base_url, credentials=_FAKE_CREDENTIALS)


class TestCreatePaymentHappyPath:
    """Verify successful payment creation."""

    @respx.mock
    def test_returns_parsed_response(self) -> None:
        route = respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json=_VALID_RESPONSE))
        client = _make_client()

        result = client.create_payment(_make_request(client_token="my-token"))

        assert result.payment_id == "awsmp-01970f3e-4b2a-7dc0-8e1f-6a3b9c5d7e2f"
        assert result.payment_token.startswith("eyJ")
        assert result.created_at == "2026-06-01T12:00:00Z"
        assert route.called

    @respx.mock
    def test_sends_quote_token_and_client_token_in_body(self) -> None:
        route = respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json=_VALID_RESPONSE))
        client = _make_client()

        client.create_payment(_make_request(quote_token="qt-123", client_token="ct-456"))

        body = json.loads(route.calls[0].request.content)
        assert body["quoteToken"] == "qt-123"
        assert body["clientToken"] == "ct-456"


class TestClientToken:
    """clientToken is included only when explicitly provided."""

    @respx.mock
    def test_omits_client_token_when_not_provided(self) -> None:
        route = respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json=_VALID_RESPONSE))
        client = _make_client()

        client.create_payment(_make_request())

        body = json.loads(route.calls[0].request.content)
        assert "clientToken" not in body

    @respx.mock
    def test_preserves_explicit_client_token(self) -> None:
        route = respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json=_VALID_RESPONSE))
        client = _make_client()

        client.create_payment(_make_request(client_token="explicit-token"))

        body = json.loads(route.calls[0].request.content)
        assert body["clientToken"] == "explicit-token"


class TestDpopJwk:
    """Verify dpopJwk is included in the request body when provided."""

    @respx.mock
    def test_includes_dpop_jwk_in_body(self) -> None:
        route = respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json=_VALID_RESPONSE))
        client = _make_client()
        request = CreateAgentPaymentRequest.model_validate(
            {
                "quoteToken": "eyJ...",
                "clientToken": "tok",
                "dpopJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                },
            }
        )

        client.create_payment(request)

        body = json.loads(route.calls[0].request.content)
        assert body["dpopJwk"]["kty"] == "EC"
        assert body["dpopJwk"]["crv"] == "P-256"


class TestSigV4Headers:
    """Verify SigV4 signing produces the required headers."""

    @respx.mock
    def test_request_includes_authorization_header(self) -> None:
        route = respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json=_VALID_RESPONSE))
        client = _make_client()

        client.create_payment(_make_request(client_token="tok"))

        headers = dict(route.calls[0].request.headers)
        assert headers["authorization"].startswith("AWS4-HMAC-SHA256")
        assert "x-amz-date" in headers
        assert "x-amz-security-token" in headers

    @respx.mock
    def test_sigv4_uses_aws_marketplace_service(self) -> None:
        route = respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json=_VALID_RESPONSE))
        client = _make_client()

        client.create_payment(_make_request(client_token="tok"))

        auth_header = dict(route.calls[0].request.headers)["authorization"]
        assert "aws-marketplace" in auth_header

    @respx.mock
    def test_content_type_is_part_of_signature(self) -> None:
        route = respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json=_VALID_RESPONSE))
        client = _make_client()

        client.create_payment(_make_request(client_token="tok"))

        headers = dict(route.calls[0].request.headers)
        assert headers["content-type"] == "application/json"
        signed_headers_clause = next(
            part
            for part in headers["authorization"].split(", ")
            if part.startswith("SignedHeaders=")
        )
        assert "content-type" in signed_headers_clause

    @respx.mock
    def test_sends_unsigned_when_no_authenticator(self) -> None:
        route = respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json=_VALID_RESPONSE))
        client = AgentPayClient(base_url=_TEST_BASE_URL)

        client.create_payment(_make_request(client_token="tok"))

        headers = dict(route.calls[0].request.headers)
        assert "authorization" not in headers

    def test_rejects_both_authenticator_and_credentials(self) -> None:
        from fiat_extension_x402.auth import AwsSigV4Authenticator

        with pytest.raises(ValueError, match="not both"):
            AgentPayClient(
                base_url=_TEST_BASE_URL,
                authenticator=AwsSigV4Authenticator(_FAKE_CREDENTIALS),
                credentials=_FAKE_CREDENTIALS,
            )

    @respx.mock
    def test_accepts_explicit_authenticator(self) -> None:
        from fiat_extension_x402.auth import AwsSigV4Authenticator

        route = respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json=_VALID_RESPONSE))
        client = AgentPayClient(
            base_url=_TEST_BASE_URL,
            authenticator=AwsSigV4Authenticator(_FAKE_CREDENTIALS),
        )

        client.create_payment(_make_request(client_token="tok"))

        headers = dict(route.calls[0].request.headers)
        assert headers["authorization"].startswith("AWS4-HMAC-SHA256")


class TestErrorHandling:
    """HTTP, conflict, network, and parse failures all surface as typed errors."""

    @respx.mock
    def test_http_error_raises_validation_error(self) -> None:
        respx.post(_CREATE_URL).mock(
            return_value=httpx.Response(400, json={"message": "Invalid quote token signature"})
        )
        client = _make_client()

        with pytest.raises(ValidationError) as exc_info:
            client.create_payment(_make_request(client_token="t"))

        assert "400" in str(exc_info.value)
        assert "Invalid quote token signature" in str(exc_info.value)

    @respx.mock
    def test_403_raises_validation_error(self) -> None:
        respx.post(_CREATE_URL).mock(
            return_value=httpx.Response(403, json={"message": "Spending limit exceeded"})
        )
        client = _make_client()

        with pytest.raises(ValidationError) as exc_info:
            client.create_payment(_make_request(client_token="t"))

        assert "403" in str(exc_info.value)

    @respx.mock
    def test_409_with_client_token_raises_idempotency_conflict(self) -> None:
        respx.post(_CREATE_URL).mock(
            return_value=httpx.Response(409, json={"message": "different params"})
        )
        client = _make_client()

        with pytest.raises(IdempotencyConflictError) as exc_info:
            client.create_payment(_make_request(client_token="dup-token"))

        assert exc_info.value.client_token == "dup-token"

    @respx.mock
    def test_409_without_client_token_raises_validation_error(self) -> None:
        respx.post(_CREATE_URL).mock(return_value=httpx.Response(409, json={"message": "conflict"}))
        client = _make_client()

        with pytest.raises(ValidationError):
            client.create_payment(_make_request())

    @respx.mock
    def test_non_2xx_redirect_is_not_success(self) -> None:
        respx.post(_CREATE_URL).mock(return_value=httpx.Response(302, json=_VALID_RESPONSE))
        client = _make_client()

        with pytest.raises(ValidationError):
            client.create_payment(_make_request(client_token="t"))

    @respx.mock
    def test_error_with_unparseable_body(self) -> None:
        respx.post(_CREATE_URL).mock(
            return_value=httpx.Response(502, content=b"<html>bad gateway</html>")
        )
        client = _make_client()

        with pytest.raises(ValidationError) as exc_info:
            client.create_payment(_make_request(client_token="t"))

        assert "502" in str(exc_info.value)

    @respx.mock
    def test_network_error_wrapped_in_validation_error(self) -> None:
        respx.post(_CREATE_URL).mock(side_effect=httpx.ConnectTimeout("connection timed out"))
        client = _make_client()

        with pytest.raises(ValidationError) as exc_info:
            client.create_payment(_make_request(client_token="t"))

        assert "Failed to authorize payment" in str(exc_info.value)

    @respx.mock
    def test_non_json_success_body_wrapped_in_validation_error(self) -> None:
        respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, content=b"not json"))
        client = _make_client()

        with pytest.raises(ValidationError) as exc_info:
            client.create_payment(_make_request(client_token="t"))

        assert "Failed to authorize payment" in str(exc_info.value)

    @respx.mock
    def test_malformed_success_schema_wrapped_in_validation_error(self) -> None:
        respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json={"unexpected": "shape"}))
        client = _make_client()

        with pytest.raises(ValidationError) as exc_info:
            client.create_payment(_make_request(client_token="t"))

        assert "Failed to authorize payment" in str(exc_info.value)


class TestDefaultBaseUrl:
    """Verify default base URL constant and URL handling."""

    def test_default_url_is_production(self) -> None:
        assert DEFAULT_BASE_URL == "https://prod.agentpay.marketplace.aws.dev"

    @respx.mock
    def test_trailing_slash_stripped(self) -> None:
        respx.post(_CREATE_URL).mock(return_value=httpx.Response(201, json=_VALID_RESPONSE))
        client = AgentPayClient(base_url=f"{_TEST_BASE_URL}/", credentials=_FAKE_CREDENTIALS)

        result = client.create_payment(_make_request(client_token="t"))

        assert result.payment_id is not None


class TestClientGetPayment:
    @respx.mock
    def test_success(self) -> None:
        from fiat_extension_x402.client import AgentPayClient

        response_body: dict[str, object] = {
            "payment": {
                "paymentId": "awsmp-12345678-1234-1234-1234-123456789012",
                "buyerAccountId": "123456789012",
                "sellerInformation": {
                    "sellerProfileId": "sp-1",
                    "displayName": "Seller",
                },
                "productId": "prod-1",
                "quoteToken": "qt",
                "paymentToken": "pt",
                "createdAt": "2025-01-01T00:00:00Z",
                "amount": {"value": "1.00", "currency": "USD"},
            }
        }
        respx.get(
            "https://test.example.com/GetAgentPayment/awsmp-12345678-1234-1234-1234-123456789012"
        ).mock(return_value=httpx.Response(200, json=response_body))

        client = AgentPayClient(base_url="https://test.example.com")
        result = client.get_payment("awsmp-12345678-1234-1234-1234-123456789012")
        assert result.payment.payment_id == "awsmp-12345678-1234-1234-1234-123456789012"

    @respx.mock
    def test_error(self) -> None:
        from fiat_extension_x402.client import AgentPayClient

        respx.get("https://test.example.com/GetAgentPayment/bad-id").mock(
            return_value=httpx.Response(404, json={"message": "not found"})
        )
        client = AgentPayClient(base_url="https://test.example.com")
        with pytest.raises(ValidationError, match="not found"):
            client.get_payment("bad-id")


class TestClientListPayments:
    @respx.mock
    def test_success(self) -> None:
        from fiat_extension_x402.client import AgentPayClient

        response_body: dict[str, object] = {"payments": [], "nextToken": None}
        respx.post("https://test.example.com/ListAgentPayments").mock(
            return_value=httpx.Response(200, json=response_body)
        )
        client = AgentPayClient(base_url="https://test.example.com")
        result = client.list_payments()
        assert result.payments == []

    @respx.mock
    def test_accepts_a_typed_request(self) -> None:
        """The typed model serializes to the camelCase body the service expects."""
        from fiat_extension_x402.client import AgentPayClient
        from fiat_extension_x402.schemas import (
            ListAgentPaymentsRequest,
            ListAgentPaymentsSort,
        )

        route = respx.post("https://test.example.com/ListAgentPayments").mock(
            return_value=httpx.Response(200, json={"payments": []})
        )
        client = AgentPayClient(base_url="https://test.example.com")
        client.list_payments(
            ListAgentPaymentsRequest(
                max_results=25,
                next_token="tok-1",
                sort=ListAgentPaymentsSort(sort_by="CreatedAt", sort_order="Desc"),
            )
        )

        sent = json.loads(route.calls[0].request.content)
        assert sent == {
            "maxResults": 25,
            "nextToken": "tok-1",
            "sort": {"sortBy": "CreatedAt", "sortOrder": "Desc"},
        }

    @respx.mock
    def test_still_accepts_a_raw_dict(self) -> None:
        from fiat_extension_x402.client import AgentPayClient

        route = respx.post("https://test.example.com/ListAgentPayments").mock(
            return_value=httpx.Response(200, json={"payments": []})
        )
        client = AgentPayClient(base_url="https://test.example.com")
        client.list_payments({"maxResults": 10})

        assert json.loads(route.calls[0].request.content) == {"maxResults": 10}

    @respx.mock
    def test_error(self) -> None:
        from fiat_extension_x402.client import AgentPayClient

        respx.post("https://test.example.com/ListAgentPayments").mock(
            return_value=httpx.Response(500, json={"message": "internal error"})
        )
        client = AgentPayClient(base_url="https://test.example.com")
        with pytest.raises(ValidationError, match="internal error"):
            client.list_payments()


class TestClientWithAuthenticator:
    """Test client methods with authenticator to cover line 141, 190."""

    @respx.mock
    def test_get_payment_with_authenticator(self) -> None:
        from fiat_extension_x402.client import AgentPayClient

        class DummyAuth:
            def authenticate(self, req: SignedRequest) -> SignedRequest:
                return SignedRequest(
                    url=req.url,
                    method=req.method,
                    headers={**req.headers, "Authorization": "Bearer test"},
                    body=req.body,
                )

        response_body: dict[str, object] = {
            "payment": {
                "paymentId": "awsmp-12345678-1234-1234-1234-123456789012",
                "buyerAccountId": "123456789012",
                "sellerInformation": {
                    "sellerProfileId": "sp-1",
                    "displayName": "Seller",
                },
                "productId": "prod-1",
                "quoteToken": "qt",
                "paymentToken": "pt",
                "createdAt": "2025-01-01T00:00:00Z",
                "amount": {"value": "1.00", "currency": "USD"},
            }
        }
        respx.get(
            "https://test.example.com/GetAgentPayment/awsmp-12345678-1234-1234-1234-123456789012"
        ).mock(return_value=httpx.Response(200, json=response_body))

        client = AgentPayClient(base_url="https://test.example.com", authenticator=DummyAuth())
        result = client.get_payment("awsmp-12345678-1234-1234-1234-123456789012")
        assert result.payment.payment_id == "awsmp-12345678-1234-1234-1234-123456789012"

    @respx.mock
    def test_list_payments_with_authenticator(self) -> None:
        from fiat_extension_x402.client import AgentPayClient

        class DummyAuth:
            def authenticate(self, req: SignedRequest) -> SignedRequest:
                return SignedRequest(
                    url=req.url,
                    method=req.method,
                    headers={**req.headers, "Authorization": "Bearer test"},
                    body=req.body,
                )

        response_body: dict[str, object] = {"payments": [], "nextToken": None}
        respx.post("https://test.example.com/ListAgentPayments").mock(
            return_value=httpx.Response(200, json=response_body)
        )

        client = AgentPayClient(base_url="https://test.example.com", authenticator=DummyAuth())
        result = client.list_payments({"maxResults": 10})
        assert result.payments == []


class TestClientNonJsonError:
    """Test client methods returning non-JSON error bodies."""

    @respx.mock
    def test_get_payment_non_json_error(self) -> None:
        from fiat_extension_x402.client import AgentPayClient

        respx.get("https://test.example.com/GetAgentPayment/x").mock(
            return_value=httpx.Response(500, text="Server Error")
        )
        client = AgentPayClient(base_url="https://test.example.com")
        with pytest.raises(ValidationError):
            client.get_payment("x")

    @respx.mock
    def test_list_payments_non_json_error(self) -> None:
        from fiat_extension_x402.client import AgentPayClient

        respx.post("https://test.example.com/ListAgentPayments").mock(
            return_value=httpx.Response(500, text="Server Error")
        )
        client = AgentPayClient(base_url="https://test.example.com")
        with pytest.raises(ValidationError):
            client.list_payments()


class TestClientGenericException:
    """Test client methods raising unexpected exceptions."""

    @respx.mock
    def test_get_payment_connection_error(self) -> None:
        from fiat_extension_x402.client import AgentPayClient

        respx.get("https://test.example.com/GetAgentPayment/x").mock(
            side_effect=ConnectionError("connection refused")
        )
        client = AgentPayClient(base_url="https://test.example.com")
        with pytest.raises(ValidationError, match="Failed to get payment"):
            client.get_payment("x")

    @respx.mock
    def test_list_payments_connection_error(self) -> None:
        from fiat_extension_x402.client import AgentPayClient

        respx.post("https://test.example.com/ListAgentPayments").mock(
            side_effect=ConnectionError("connection refused")
        )
        client = AgentPayClient(base_url="https://test.example.com")
        with pytest.raises(ValidationError, match="Failed to list payments"):
            client.list_payments()


class TestClientVerifyPaymentToken:
    """`verify_payment_token` checks a token against Agent Pay's published keys."""

    @staticmethod
    def _keypair() -> tuple[Any, dict[str, Any]]:
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP384R1,
            generate_private_key,
        )

        key = generate_private_key(SECP384R1())
        numbers = key.public_key().public_numbers()

        def b64(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        jwk = {
            "kty": "EC",
            "crv": "P-384",
            "x": b64(numbers.x.to_bytes(48, "big")),
            "y": b64(numbers.y.to_bytes(48, "big")),
            "kid": "ap-key-1",
            "use": "sig",
            "alg": "ES384",
        }
        return key, jwk

    @classmethod
    def _token(cls, key: Any, *, kid: str = "ap-key-1") -> str:
        import jwt as pyjwt

        now = int(time.time())
        return str(
            pyjwt.encode(
                {
                    "iss": "awsmp-agentpay.amazonaws.com",
                    "aud": "https://seller.example.com",
                    "iat": now,
                    "exp": now + 3600,
                    "sub": "111122223333",
                    "payment_id": "awsmp-00000000-0000-0000-0000-000000000001",
                    "quote_token": "eyJ.quote",
                },
                key,
                algorithm="ES384",
                headers={"kid": kid},
            )
        )

    @respx.mock
    def test_verifies_a_genuine_token(self) -> None:
        from fiat_extension_x402.client import AgentPayClient
        from fiat_extension_x402.constants import WELL_KNOWN_JWKS_PATH

        key, jwk = self._keypair()
        route = respx.get(f"{_TEST_BASE_URL}{WELL_KNOWN_JWKS_PATH}").mock(
            return_value=httpx.Response(200, json={"keys": [jwk]})
        )

        client = AgentPayClient(base_url=_TEST_BASE_URL)
        claims = client.verify_payment_token(self._token(key))

        assert claims.iss == "awsmp-agentpay.amazonaws.com"
        assert claims.sub == "111122223333"
        assert claims.payment_id == "awsmp-00000000-0000-0000-0000-000000000001"
        # Agent Pay's JWKS endpoint sits behind a WAF that expects this header.
        assert route.calls[0].request.headers["x-agentpay-key"]

    @respx.mock
    def test_rejects_an_expired_token(self) -> None:
        """A payment token past its `exp` is not genuine for present use."""
        import jwt as pyjwt

        from fiat_extension_x402.client import AgentPayClient
        from fiat_extension_x402.constants import WELL_KNOWN_JWKS_PATH

        key, jwk = self._keypair()
        respx.get(f"{_TEST_BASE_URL}{WELL_KNOWN_JWKS_PATH}").mock(
            return_value=httpx.Response(200, json={"keys": [jwk]})
        )
        now = int(time.time())
        expired = pyjwt.encode(
            {
                "iss": "awsmp-agentpay.amazonaws.com",
                "aud": "https://seller.example.com",
                "iat": now - 7200,
                "exp": now - 3600,
                "sub": "111122223333",
                "payment_id": "awsmp-00000000-0000-0000-0000-000000000001",
            },
            key,
            algorithm="ES384",
            headers={"kid": "ap-key-1"},
        )

        client = AgentPayClient(base_url=_TEST_BASE_URL)
        with pytest.raises(ValidationError, match="expired"):
            client.verify_payment_token(expired)

    @respx.mock
    def test_rejects_a_tampered_token(self) -> None:
        from fiat_extension_x402.client import AgentPayClient
        from fiat_extension_x402.constants import WELL_KNOWN_JWKS_PATH

        key, jwk = self._keypair()
        respx.get(f"{_TEST_BASE_URL}{WELL_KNOWN_JWKS_PATH}").mock(
            return_value=httpx.Response(200, json={"keys": [jwk]})
        )

        tampered = self._token(key)[:-6] + "AAAAAA"
        client = AgentPayClient(base_url=_TEST_BASE_URL)
        with pytest.raises(ValidationError, match="Failed to verify payment token"):
            client.verify_payment_token(tampered)

    @respx.mock
    def test_rejects_an_unknown_signing_key(self) -> None:
        from fiat_extension_x402.client import AgentPayClient
        from fiat_extension_x402.constants import WELL_KNOWN_JWKS_PATH

        key, jwk = self._keypair()
        respx.get(f"{_TEST_BASE_URL}{WELL_KNOWN_JWKS_PATH}").mock(
            return_value=httpx.Response(200, json={"keys": [{**jwk, "kid": "someone-else"}]})
        )

        client = AgentPayClient(base_url=_TEST_BASE_URL)
        with pytest.raises(ValidationError, match="No Agent Pay signing key"):
            client.verify_payment_token(self._token(key))

    @respx.mock
    def test_surfaces_a_jwks_fetch_failure(self) -> None:
        from fiat_extension_x402.client import AgentPayClient
        from fiat_extension_x402.constants import WELL_KNOWN_JWKS_PATH

        respx.get(f"{_TEST_BASE_URL}{WELL_KNOWN_JWKS_PATH}").mock(return_value=httpx.Response(403))

        client = AgentPayClient(base_url=_TEST_BASE_URL)
        with pytest.raises(ValidationError, match="Failed to fetch Agent Pay public keys"):
            client.verify_payment_token("eyJ.a.b")
