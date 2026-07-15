# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Pydantic schema validation tests.

Covers serialization/deserialization of every model, the camelCase wire-format aliases,
and the JWT-claim models (``PaymentTokenPayload`` / ``PaymentJwtClaims``,
``AgentPayPaymentExtra``).
"""

import time

import jwt
import pytest
from pydantic import ValidationError

from fiat_extension_x402.schemas import (
    AgentPayPaymentExtra,
    AgentPayPayloadV2,
    AgentPaySettlement,
    AgentPaySupport,
    AgentPayTerms,
    CreateAgentPaymentRequest,
    CreateAgentPaymentResponse,
    DpopJwk,
    GetAgentPaymentResponse,
    ListAgentPaymentsResponse,
    PaymentTokenPayload,
    QuoteTokenPayload,
    QuoteTokenPrice,
    parse_create_payment_response,
    parse_payment_payload,
    parse_quote_token,
    safe_parse_quote_token,
)

VALID_QUOTE_PAYLOAD = {
    "iss": "https://api.example.com",
    "aud": "aws-marketplace",
    "iat": 1700000000,
    "exp": 1700000300,
    "jti": "quote-001",
    "price": {"amount": "0.15", "currency": "USD"},
    "payTo": "seller-123",
    "reference": "API_ACCESS",
}


def _sign_jwt(claims: dict[str, object]) -> str:
    """Sign ``claims`` into a compact JWT (HS256) for decode-only parse tests."""
    return jwt.encode(claims, "test-signing-secret-key-32-bytes-long", algorithm="HS256")


class TestQuoteTokenPrice:
    def test_accepts_valid_price(self) -> None:
        price = QuoteTokenPrice.model_validate({"amount": "0.15", "currency": "USD"})
        assert price.amount == "0.15"
        assert price.currency == "USD"

    def test_rejects_non_decimal_amount(self) -> None:
        with pytest.raises(ValidationError):
            QuoteTokenPrice.model_validate({"amount": "abc", "currency": "USD"})

    def test_rejects_invalid_currency_length(self) -> None:
        with pytest.raises(ValidationError):
            QuoteTokenPrice.model_validate({"amount": "1.00", "currency": "US"})
        with pytest.raises(ValidationError):
            QuoteTokenPrice.model_validate({"amount": "1.00", "currency": "USDD"})


class TestAgentPaySettlement:
    def test_accepts_valid_settlement(self) -> None:
        assert AgentPaySettlement.model_validate({"method": "INST"}).method == "INST"
        full = AgentPaySettlement.model_validate({"method": "CLRG", "cycle": "MNTH"})
        assert full.cycle == "MNTH"

    def test_rejects_invalid_method(self) -> None:
        with pytest.raises(ValidationError):
            AgentPaySettlement.model_validate({"method": "INVALID"})


class TestAgentPaySupport:
    def test_accepts_valid_support(self) -> None:
        result = AgentPaySupport.model_validate(
            {"uri": "https://support.example.com", "method": "human"}
        )
        assert result.method == "human"

    def test_rejects_invalid_uri(self) -> None:
        with pytest.raises(ValidationError):
            AgentPaySupport.model_validate({"uri": "not-a-url", "method": "human"})

    def test_rejects_invalid_method(self) -> None:
        with pytest.raises(ValidationError):
            AgentPaySupport.model_validate({"uri": "https://x.com", "method": "bot"})


class TestAgentPayTerms:
    def test_accepts_valid_terms(self) -> None:
        result = AgentPayTerms.model_validate(
            {"description": "TOS", "uri": "https://example.com/tos"}
        )
        assert result.description == "TOS"

    def test_rejects_empty_description(self) -> None:
        with pytest.raises(ValidationError):
            AgentPayTerms.model_validate({"description": "", "uri": "https://x.com"})


class TestQuoteTokenPayload:
    def test_accepts_valid_payload(self) -> None:
        result = QuoteTokenPayload.model_validate(VALID_QUOTE_PAYLOAD)
        assert result.iss == "https://api.example.com"
        assert result.pay_to == "seller-123"

    def test_accepts_payload_with_optional_fields(self) -> None:
        result = QuoteTokenPayload.model_validate(
            {
                **VALID_QUOTE_PAYLOAD,
                "description": "Premium API access",
                "dimensions": {"tokens": 1500, "model": "claude-4"},
                "settlement": {"method": "INST"},
                "support": {"uri": "https://support.example.com", "method": "agent"},
                "terms": [{"description": "TOS", "uri": "https://example.com/tos"}],
            }
        )
        assert result.description == "Premium API access"
        assert result.dimensions == {"tokens": 1500, "model": "claude-4"}

    def test_accepts_array_of_prices(self) -> None:
        result = QuoteTokenPayload.model_validate(
            {
                **VALID_QUOTE_PAYLOAD,
                "price": [
                    {"amount": "0.15", "currency": "USD"},
                    {"amount": "0.13", "currency": "EUR"},
                ],
            }
        )
        assert isinstance(result.price, list)

    def test_accepts_array_aud(self) -> None:
        result = QuoteTokenPayload.model_validate(
            {**VALID_QUOTE_PAYLOAD, "aud": ["aws:base", "other:net"]}
        )
        assert result.aud == ["aws:base", "other:net"]

    def test_rejects_missing_required_fields(self) -> None:
        with pytest.raises(ValidationError):
            QuoteTokenPayload.model_validate({"iss": "x"})
        with pytest.raises(ValidationError):
            QuoteTokenPayload.model_validate({**VALID_QUOTE_PAYLOAD, "jti": None})

    def test_rejects_non_integer_iat(self) -> None:
        with pytest.raises(ValidationError):
            QuoteTokenPayload.model_validate({**VALID_QUOTE_PAYLOAD, "iat": 1.5})

    def test_wire_format_round_trips_to_camel_case(self) -> None:
        # payTo is the one camelCase key on this otherwise snake_case JWT claim model.
        result = QuoteTokenPayload.model_validate(VALID_QUOTE_PAYLOAD)
        dumped = result.model_dump(by_alias=True, exclude_none=True)
        assert dumped["payTo"] == "seller-123"
        assert "pay_to" not in dumped


class TestPaymentTokenPayload:
    """PaymentJwtClaims — snake_case wire keys, signed by Agent Pay."""

    def test_accepts_minimal_claims(self) -> None:
        result = PaymentTokenPayload.model_validate(
            {
                "iss": "awsmp-agentpay.amazonaws.com",
                "aud": "https://seller.example.com",
                "iat": 1700000000,
                "exp": 1700003600,
            }
        )
        assert result.iss == "awsmp-agentpay.amazonaws.com"
        assert result.payment_id is None

    def test_accepts_full_claims(self) -> None:
        result = PaymentTokenPayload.model_validate(
            {
                "iss": "awsmp-agentpay.amazonaws.com",
                "aud": "https://seller.example.com",
                "iat": 1700000000,
                "exp": 1700003600,
                "sub": "buyer-1",
                "payment_id": "awsmp-01970f3e-4b2a-7dc0-8e1f-6a3b9c5d7e2f",
                "quote_token": "eyJ...",
                "jti": "awsmp-01970f3e-4b2a-7dc0-8e1f-6a3b9c5d7e2f",
                "cnf": {"jkt": "abc123"},
            }
        )
        assert result.payment_id is not None
        assert result.cnf is not None
        assert result.cnf.jkt == "abc123"

    def test_rejects_missing_required_fields(self) -> None:
        with pytest.raises(ValidationError):
            PaymentTokenPayload.model_validate({"iss": "x"})


class TestAgentPayPaymentExtra:
    """AgentPayPaymentExtra — camelCase wire keys, lives in PaymentRequirements.extra."""

    def test_accepts_minimal_extra(self) -> None:
        result = AgentPayPaymentExtra.model_validate({"quoteToken": "eyJ..."})
        assert result.quote_token == "eyJ..."

    def test_round_trips_to_camel_case(self) -> None:
        result = AgentPayPaymentExtra.model_validate({"quoteToken": "eyJ...", "reference": "API"})
        dumped = result.model_dump(by_alias=True, exclude_none=True)
        assert dumped == {"quoteToken": "eyJ...", "reference": "API"}

    def test_rejects_empty_quote_token(self) -> None:
        with pytest.raises(ValidationError):
            AgentPayPaymentExtra.model_validate({"quoteToken": ""})


class TestAgentPayPayloadV2:
    def test_accepts_valid_payload(self) -> None:
        result = AgentPayPayloadV2.model_validate(
            {"paymentToken": "eyJ...", "paymentId": "awsmp-123"}
        )
        assert result.payment_id == "awsmp-123"

    def test_accepts_with_transaction_id(self) -> None:
        result = AgentPayPayloadV2.model_validate(
            {"paymentToken": "eyJ...", "paymentId": "awsmp-123", "transactionId": "awsmp-123"}
        )
        assert result.transaction_id == "awsmp-123"

    def test_rejects_missing_payment_token(self) -> None:
        with pytest.raises(ValidationError):
            AgentPayPayloadV2.model_validate({"paymentId": "x"})

    def test_round_trips_to_camel_case(self) -> None:
        result = AgentPayPayloadV2.model_validate(
            {"paymentToken": "eyJ...", "paymentId": "awsmp-123"}
        )
        dumped = result.model_dump(by_alias=True, exclude_none=True)
        assert dumped == {"paymentToken": "eyJ...", "paymentId": "awsmp-123"}


class TestDpopJwk:
    def test_accepts_valid_ec_key(self) -> None:
        result = DpopJwk.model_validate(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            }
        )
        assert result.kty == "EC"
        assert result.crv == "P-256"

    def test_rejects_non_ec_kty(self) -> None:
        with pytest.raises(ValidationError):
            DpopJwk.model_validate({"kty": "RSA", "crv": "P-256", "x": "a" * 43, "y": "b" * 43})

    def test_rejects_unsupported_curve(self) -> None:
        with pytest.raises(ValidationError):
            DpopJwk.model_validate({"kty": "EC", "crv": "P-192", "x": "a" * 43, "y": "b" * 43})

    def test_rejects_short_xy_values(self) -> None:
        with pytest.raises(ValidationError):
            DpopJwk.model_validate({"kty": "EC", "crv": "P-256", "x": "short", "y": "short"})


class TestCreateAgentPaymentRequest:
    def test_accepts_minimal_request(self) -> None:
        result = CreateAgentPaymentRequest.model_validate({"quoteToken": "eyJ..."})
        assert result.quote_token == "eyJ..."
        assert result.client_token is None

    def test_accepts_full_request(self) -> None:
        result = CreateAgentPaymentRequest.model_validate(
            {
                "quoteToken": "eyJ...",
                "clientToken": "idem-123",
                "dpopJwk": {"kty": "EC", "crv": "P-256", "x": "a" * 43, "y": "b" * 43},
            }
        )
        assert result.client_token == "idem-123"

    def test_rejects_empty_quote_token(self) -> None:
        with pytest.raises(ValidationError):
            CreateAgentPaymentRequest.model_validate({"quoteToken": ""})

    def test_rejects_client_token_over_128_chars(self) -> None:
        with pytest.raises(ValidationError):
            CreateAgentPaymentRequest.model_validate({"quoteToken": "x", "clientToken": "a" * 129})

    def test_round_trips_to_camel_case(self) -> None:
        result = CreateAgentPaymentRequest.model_validate(
            {"quoteToken": "eyJ...", "clientToken": "idem-123"}
        )
        dumped = result.model_dump(by_alias=True, exclude_none=True)
        assert dumped == {"quoteToken": "eyJ...", "clientToken": "idem-123"}


class TestCreateAgentPaymentResponse:
    def test_accepts_valid_response(self) -> None:
        result = CreateAgentPaymentResponse.model_validate(
            {
                "paymentId": "awsmp-01970f3e-4b2a-7dc0-8e1f-6a3b9c5d7e2f",
                "paymentToken": "eyJ...",
                "createdAt": "2026-05-12T00:00:00Z",
            }
        )
        assert "awsmp-" in result.payment_id

    def test_rejects_invalid_payment_id_format(self) -> None:
        with pytest.raises(ValidationError):
            CreateAgentPaymentResponse.model_validate(
                {
                    "paymentId": "invalid-id",
                    "paymentToken": "x",
                    "createdAt": "2026-01-01T00:00:00Z",
                }
            )

    def test_rejects_invalid_created_at_format(self) -> None:
        with pytest.raises(ValidationError):
            CreateAgentPaymentResponse.model_validate(
                {
                    "paymentId": "awsmp-01970f3e-4b2a-7dc0-8e1f-6a3b9c5d7e2f",
                    "paymentToken": "x",
                    "createdAt": "not-a-date",
                }
            )


class TestGetAndListResponses:
    def _payment_detail(self) -> dict[str, object]:
        return {
            "paymentId": "awsmp-01970f3e-4b2a-7dc0-8e1f-6a3b9c5d7e2f",
            "buyerAccountId": "123456789012",
            "sellerInformation": {"sellerProfileId": "sp-1", "displayName": "Acme"},
            "productId": "prod-1",
            "quoteToken": "eyJ...",
            "paymentToken": "eyJ...",
            "createdAt": "2026-05-12T00:00:00Z",
            "amount": {"value": "0.15", "currency": "USD"},
        }

    def test_get_payment_response(self) -> None:
        result = GetAgentPaymentResponse.model_validate({"payment": self._payment_detail()})
        assert result.payment.buyer_account_id == "123456789012"
        assert result.payment.seller_information.display_name == "Acme"

    def test_get_payment_rejects_bad_buyer_account_id(self) -> None:
        detail = self._payment_detail()
        detail["buyerAccountId"] = "123"
        with pytest.raises(ValidationError):
            GetAgentPaymentResponse.model_validate({"payment": detail})

    def test_list_payments_response_with_next_token(self) -> None:
        result = ListAgentPaymentsResponse.model_validate(
            {
                "payments": [
                    {
                        "paymentId": "awsmp-1",
                        "buyerAccountId": "123456789012",
                        "sellerInformation": {"sellerProfileId": "sp-1", "displayName": "Acme"},
                        "productId": "prod-1",
                        "createdAt": "2026-05-12T00:00:00Z",
                    }
                ],
                "nextToken": "tok",
            }
        )
        assert len(result.payments) == 1
        assert result.next_token == "tok"

    def test_list_payments_empty(self) -> None:
        result = ListAgentPaymentsResponse.model_validate({"payments": []})
        assert result.payments == []
        assert result.next_token is None


class TestParseQuoteToken:
    def test_decodes_and_validates_valid_token(self) -> None:
        now = int(time.time())
        token = _sign_jwt(
            {
                "iss": "https://api.example.com",
                "aud": "aws-marketplace",
                "iat": now,
                "exp": now + 300,
                "jti": "q-123",
                "price": {"amount": "1.00", "currency": "USD"},
                "payTo": "seller",
                "reference": "TEST",
            }
        )
        result = parse_quote_token(token)
        assert result.iss == "https://api.example.com"
        assert result.pay_to == "seller"

    def test_throws_on_invalid_jwt(self) -> None:
        with pytest.raises(jwt.PyJWTError):
            parse_quote_token("not-a-jwt")

    def test_throws_on_valid_jwt_with_missing_fields(self) -> None:
        token = _sign_jwt({"iss": "x"})
        with pytest.raises(ValidationError):
            parse_quote_token(token)


class TestSafeParseQuoteToken:
    def test_returns_success_for_valid_token(self) -> None:
        now = int(time.time())
        token = _sign_jwt(
            {
                "iss": "https://api.example.com",
                "aud": "aws-marketplace",
                "iat": now,
                "exp": now + 300,
                "jti": "q-456",
                "price": {"amount": "0.50", "currency": "USD"},
                "payTo": "seller",
                "reference": "TEST",
            }
        )
        result = safe_parse_quote_token(token)
        assert result.success is True
        assert result.data is not None
        assert result.data.jti == "q-456"

    def test_returns_error_for_invalid_jwt(self) -> None:
        result = safe_parse_quote_token("garbage")
        assert result.success is False
        assert result.error is not None

    def test_returns_error_for_valid_jwt_with_missing_fields(self) -> None:
        result = safe_parse_quote_token(_sign_jwt({"iss": "x"}))
        assert result.success is False
        assert isinstance(result.error, ValidationError)


class TestParsePaymentPayload:
    def test_validates_valid_payload(self) -> None:
        result = parse_payment_payload({"paymentToken": "tok", "paymentId": "awsmp-123"})
        assert result.payment_id == "awsmp-123"

    def test_throws_on_missing_fields(self) -> None:
        with pytest.raises(ValidationError):
            parse_payment_payload({"paymentToken": "tok"})


class TestParseCreatePaymentResponse:
    def test_validates_valid_response(self) -> None:
        result = parse_create_payment_response(
            {
                "paymentId": "awsmp-01970f3e-4b2a-7dc0-8e1f-6a3b9c5d7e2f",
                "paymentToken": "eyJ...",
                "createdAt": "2026-05-12T10:00:00Z",
            }
        )
        assert "awsmp-" in result.payment_id

    def test_throws_on_invalid_response(self) -> None:
        with pytest.raises(ValidationError):
            parse_create_payment_response({"paymentId": "bad"})
