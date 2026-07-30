# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Pydantic v2 validation models for Agent Pay types.

These models provide runtime validation for untrusted input (e.g. 402 responses,
webhook payloads, decoded JWTs).

Two wire conventions are used:

* **API request/response bodies** use ``camelCase`` keys (e.g. ``quoteToken``,
  ``paymentId``). These models extend :class:`_CamelModel`, which aliases snake_case
  Python fields to camelCase on the wire. Dump with ``model_dump(by_alias=True)``.
* **JWT claims** use ``snake_case`` keys (e.g. ``payment_id``, ``quote_token``) — the
  one exception is :attr:`QuoteTokenPayload.pay_to`, whose wire key is ``payTo``. These
  models extend :class:`_Model`.

Usage::

    from fiat_extension_x402.schemas import QuoteTokenPayload, parse_quote_token

    validated = QuoteTokenPayload.model_validate(decoded)
    # or
    result = parse_quote_token(token_string)  # decode + validate
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Dict, List, Literal, Optional, Union

import jwt
from pydantic import (
    AfterValidator,
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
)
from pydantic.alias_generators import to_camel

# ============================================================================
# Base Models
# ============================================================================


class _Model(BaseModel):
    """Base for models whose wire format uses snake_case keys (JWT claims)."""

    model_config = ConfigDict(populate_by_name=True)


class _CamelModel(BaseModel):
    """Base for API models whose wire format uses camelCase keys."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


# ============================================================================
# Reusable Field Constraints
# ============================================================================

_URL_ADAPTER: TypeAdapter[AnyUrl] = TypeAdapter(AnyUrl)
_DATETIME_ADAPTER: TypeAdapter[datetime] = TypeAdapter(datetime)


def _validate_url(value: str) -> str:
    """Validate ``value`` is a URL; return it unchanged."""
    _URL_ADAPTER.validate_python(value)
    return value


def _validate_datetime(value: str) -> str:
    """Validate ``value`` is an ISO 8601 datetime."""
    _DATETIME_ADAPTER.validate_python(value)
    return value


NonEmptyStr = Annotated[str, Field(min_length=1)]
UrlStr = Annotated[str, AfterValidator(_validate_url)]
DateTimeStr = Annotated[str, AfterValidator(_validate_datetime)]
AmountStr = Annotated[str, Field(pattern=r"^\d+\.?\d*$")]
CurrencyStr = Annotated[str, Field(min_length=3, max_length=3)]

# ============================================================================
# Settlement Schemas
# ============================================================================

SettlementMethod = Literal["INST", "CLRG", "CRDT"]
SettlementCycle = Literal["MNTH", "WEEK", "QRTR"]


class AgentPaySettlement(_Model):
    """Settlement terms for a payment."""

    method: SettlementMethod
    cycle: Optional[SettlementCycle] = None


class AgentPaySupport(_Model):
    """Support contact information for disputes."""

    uri: UrlStr
    method: Literal["human", "agent"]


class AgentPayTerms(_Model):
    """Terms and conditions reference."""

    description: NonEmptyStr
    uri: UrlStr


# ============================================================================
# Price Schema
# ============================================================================


class QuoteTokenPrice(_Model):
    """Price information in a quote token."""

    amount: AmountStr
    currency: CurrencyStr


_PriceList = Annotated[List[QuoteTokenPrice], Field(min_length=1)]

# ============================================================================
# Quote Token Schema
# ============================================================================


class QuoteTokenPayload(_Model):
    """Quote token JWT payload — the signed ``quoteToken`` from the HTTP 402 response."""

    iss: NonEmptyStr
    aud: Union[NonEmptyStr, List[NonEmptyStr]]
    iat: int = Field(gt=0)
    exp: int = Field(gt=0)
    jti: NonEmptyStr
    price: Union[QuoteTokenPrice, _PriceList]
    pay_to: NonEmptyStr = Field(alias="payTo")
    reference: str
    description: Optional[str] = None
    dimensions: Optional[Dict[str, Union[str, int, float]]] = None
    settlement: Optional[AgentPaySettlement] = None
    support: Optional[AgentPaySupport] = None
    terms: Optional[List[AgentPayTerms]] = None


# ============================================================================
# Payment Token (JWT) Claims
# ============================================================================


class PaymentContext(_Model):
    """Payment context embedded in a payment token (legacy nested form)."""

    transaction_id: str
    quote_token: str


class Confirmation(_Model):
    """DPoP confirmation claim (``cnf``) carrying the public key thumbprint."""

    jkt: str


class PaymentTokenPayload(_Model):
    """Payment token JWT payload (a.k.a. ``PaymentJwtClaims``), signed by Agent Pay."""

    iss: NonEmptyStr
    aud: str
    iat: int = Field(gt=0)
    exp: int = Field(gt=0)
    sub: Optional[str] = None
    payment_id: Optional[str] = None
    quote_token: Optional[str] = None
    jti: Optional[str] = None
    payment_context: Optional[PaymentContext] = None
    cnf: Optional[Confirmation] = None


# ============================================================================
# Payment Extra Schema (Agent Pay data in x402 PaymentRequirements.extra)
# ============================================================================


class AgentPayPaymentExtra(_CamelModel):
    """Agent Pay payload stored in the ``extra`` field of x402 ``PaymentRequirements``."""

    quote_token: NonEmptyStr
    reference: Optional[str] = None
    settlement: Optional[AgentPaySettlement] = None
    support: Optional[AgentPaySupport] = None
    terms: Optional[List[AgentPayTerms]] = None


# ============================================================================
# Payment Payload Schema
# ============================================================================


class AgentPayPayloadV2(_CamelModel):
    """Agent Pay payload for the x402 ``PaymentPayload``."""

    payment_token: NonEmptyStr
    payment_id: NonEmptyStr
    transaction_id: Optional[str] = None


# ============================================================================
# DPoP JWK Schema
# ============================================================================


class DpopJwk(_Model):
    """DPoP public key in JWK format. Only EC keys (P-256, P-384, P-521) are supported."""

    kty: Literal["EC"]
    crv: Literal["P-256", "P-384", "P-521"]
    x: Annotated[str, Field(min_length=43, max_length=128)]
    y: Annotated[str, Field(min_length=43, max_length=128)]


# ============================================================================
# API Request/Response Schemas
# ============================================================================


class CreateAgentPaymentRequest(_CamelModel):
    """Request body for ``POST /CreateAgentPayment``."""

    quote_token: Annotated[str, Field(min_length=1, max_length=65536)]
    client_token: Optional[Annotated[str, Field(min_length=1, max_length=128)]] = None
    dpop_jwk: Optional[DpopJwk] = None


class CreateAgentPaymentResponse(_CamelModel):
    """Response from ``POST /CreateAgentPayment`` (201)."""

    payment_id: Annotated[str, Field(pattern=r"^awsmp-[0-9a-f-]{36}$")]
    payment_token: NonEmptyStr
    created_at: DateTimeStr


class PaymentAmount(_Model):
    """Monetary amount with ISO 4217 currency."""

    value: AmountStr
    currency: CurrencyStr


class SellerInformation(_CamelModel):
    """Seller identity attached to a payment."""

    seller_profile_id: NonEmptyStr
    display_name: NonEmptyStr


class PaymentDetail(_CamelModel):
    """Full payment record returned by ``GET /GetAgentPayment/{paymentId}``."""

    payment_id: NonEmptyStr
    buyer_account_id: Annotated[str, Field(pattern=r"^\d{12}$")]
    seller_information: SellerInformation
    product_id: NonEmptyStr
    quote_token: NonEmptyStr
    payment_token: NonEmptyStr
    created_at: DateTimeStr
    amount: PaymentAmount
    agreement_id: Optional[str] = None


class GetAgentPaymentResponse(_CamelModel):
    """Response from ``GET /GetAgentPayment/{paymentId}`` (200)."""

    payment: PaymentDetail


class PaymentSummary(_CamelModel):
    """Condensed payment record returned by ``POST /ListAgentPayments``."""

    payment_id: NonEmptyStr
    buyer_account_id: Annotated[str, Field(pattern=r"^\d{12}$")]
    seller_information: SellerInformation
    product_id: NonEmptyStr
    created_at: DateTimeStr
    agreement_id: Optional[str] = None


class ListAgentPaymentsSort(_CamelModel):
    """Sort options for ``POST /ListAgentPayments``."""

    sort_by: Optional[Literal["CreatedAt"]] = None
    sort_order: Optional[Literal["Asc", "Desc"]] = None


class ListAgentPaymentsRequest(_CamelModel):
    """Request body for ``POST /ListAgentPayments``."""

    sort: Optional[ListAgentPaymentsSort] = None
    max_results: Optional[int] = None
    next_token: Optional[str] = None


class ListAgentPaymentsResponse(_CamelModel):
    """Response from ``POST /ListAgentPayments`` (200)."""

    payments: List[PaymentSummary]
    next_token: Optional[str] = None


# ============================================================================
# Error Response Schema
# ============================================================================


class ErrorResponse(_Model):
    """Agent Pay API error response body. The ``message`` field carries the detail."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    message: Optional[str] = None


# ============================================================================
# Parse Utilities (decode + validate)
# ============================================================================


@dataclass(frozen=True)
class SafeParseResult:
    """Result of a non-throwing parse."""

    success: bool
    data: Optional[QuoteTokenPayload] = None
    error: Optional[Exception] = None


def parse_quote_token(token: str) -> QuoteTokenPayload:
    """Decode and validate a quote token JWT.

    Decodes without signature verification, then validates the payload structure.

    :param token: Quote token JWT string.
    :returns: Validated :class:`QuoteTokenPayload`.
    :raises jwt.PyJWTError: if the token is not a well-formed JWT.
    :raises pydantic.ValidationError: if the payload does not match the schema.
    """
    # Decode without signature verification, then validate the payload structure.
    # Signature verification happens later against the JWKS public key.
    decoded = jwt.decode(token, options={"verify_signature": False})
    return QuoteTokenPayload.model_validate(decoded)


def safe_parse_quote_token(token: str) -> SafeParseResult:
    """Safely decode and validate a quote token JWT.

    Returns a :class:`SafeParseResult` instead of raising.

    :param token: Quote token JWT string.
    :returns: A :class:`SafeParseResult` with ``success`` and ``data``/``error``.
    """
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
    except Exception as exc:  # noqa: BLE001 - invalid JWT format -> failure result
        return SafeParseResult(success=False, error=exc)
    try:
        data = QuoteTokenPayload.model_validate(decoded)
    except ValidationError as exc:
        return SafeParseResult(success=False, error=exc)
    return SafeParseResult(success=True, data=data)


def parse_payment_payload(payload: object) -> AgentPayPayloadV2:
    """Validate a payment payload structure.

    :param payload: Payment payload object.
    :returns: Validated :class:`AgentPayPayloadV2`.
    :raises pydantic.ValidationError: if the payload does not match the schema.
    """
    return AgentPayPayloadV2.model_validate(payload)


def parse_create_payment_response(response: object) -> CreateAgentPaymentResponse:
    """Validate a CreateAgentPayment response.

    :param response: API response object.
    :returns: Validated :class:`CreateAgentPaymentResponse`.
    :raises pydantic.ValidationError: if the response does not match the schema.
    """
    return CreateAgentPaymentResponse.model_validate(response)


__all__ = [
    "AgentPayPaymentExtra",
    "AgentPayPayloadV2",
    "AgentPaySettlement",
    "AgentPaySupport",
    "AgentPayTerms",
    "Confirmation",
    "CreateAgentPaymentRequest",
    "CreateAgentPaymentResponse",
    "DpopJwk",
    "ErrorResponse",
    "GetAgentPaymentResponse",
    "ListAgentPaymentsRequest",
    "ListAgentPaymentsResponse",
    "ListAgentPaymentsSort",
    "PaymentAmount",
    "PaymentContext",
    "PaymentDetail",
    "PaymentSummary",
    "PaymentTokenPayload",
    "QuoteTokenPayload",
    "QuoteTokenPrice",
    "SafeParseResult",
    "SellerInformation",
    "SettlementCycle",
    "SettlementMethod",
    "parse_create_payment_response",
    "parse_payment_payload",
    "parse_quote_token",
    "safe_parse_quote_token",
]
