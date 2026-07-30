# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Default Agent Pay client implementation.

Handles HTTP communication with the AWS Marketplace Agent Pay Service.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, Union, runtime_checkable

import httpx
import jwt as pyjwt
from botocore.credentials import Credentials  # type: ignore[import-untyped]

from fiat_extension_x402.auth import Authenticator, AwsSigV4Authenticator, SignedRequest
from fiat_extension_x402.constants import AGENT_PAY_JWKS_ACCESS_KEY, WELL_KNOWN_JWKS_PATH
from fiat_extension_x402.exceptions import IdempotencyConflictError, ValidationError
from fiat_extension_x402.schemas import (
    CreateAgentPaymentRequest,
    CreateAgentPaymentResponse,
    GetAgentPaymentResponse,
    ListAgentPaymentsRequest,
    ListAgentPaymentsResponse,
    PaymentTokenPayload,
)
from fiat_extension_x402.security import ALLOWED_ALGORITHMS

# Default Agent Pay endpoint (production).
DEFAULT_BASE_URL = "https://prod.agentpay.marketplace.aws.dev"


@runtime_checkable
class AgentPayClientForClient(Protocol):
    """The buyer-side Agent Pay contract.

    Deliberately one method wide: creating a payment is all the client scheme
    needs. ``get_payment``/``list_payments`` are concrete conveniences on
    :class:`AgentPayClient` rather than part of the buyer contract, so a test
    double only has to implement this one call.
    """

    def create_payment(self, request: CreateAgentPaymentRequest) -> CreateAgentPaymentResponse:
        """Exchange a seller-signed quote token for a signed payment token."""
        ...


class AgentPayClient:
    """Default Agent Pay client implementation.

    Communicates with the AWS Marketplace Agent Pay Service API.

    :param base_url: Agent Pay service base URL. Defaults to the production endpoint.
    :param authenticator: Authenticator used to sign outgoing requests.
    :param credentials: AWS credentials for SigV4 signing (mutually exclusive with
        ``authenticator``).
    :raises ValueError: if both ``authenticator`` and ``credentials`` are provided.
    """

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        authenticator: Optional[Authenticator] = None,
        credentials: Optional[Credentials] = None,
    ) -> None:
        if authenticator is not None and credentials is not None:
            raise ValueError("Provide either 'authenticator' or 'credentials', not both")

        self._base_url = base_url.rstrip("/")
        if authenticator is not None:
            self._authenticator: Optional[Authenticator] = authenticator
        elif credentials is not None:
            self._authenticator = AwsSigV4Authenticator(credentials)
        else:
            self._authenticator = None

    def create_payment(self, request: CreateAgentPaymentRequest) -> CreateAgentPaymentResponse:
        """Create a payment with the Agent Pay Service.

        Sends the seller-signed quote token; Agent Pay verifies, captures, and
        returns a signed payment JWT.

        Maps to: POST /CreateAgentPayment

        :param request: Validated payment request.
        :returns: Parsed ``CreateAgentPaymentResponse`` with ``paymentId`` and
            ``paymentToken``.
        :raises IdempotencyConflictError: clientToken reused with different parameters.
        :raises ValidationError: any other authorization failure.
        """
        url = f"{self._base_url}/CreateAgentPayment"

        body_dict: dict[str, Any] = {"quoteToken": request.quote_token}
        if request.client_token:
            body_dict["clientToken"] = request.client_token
        if request.dpop_jwk is not None:
            body_dict["dpopJwk"] = request.dpop_jwk.model_dump()

        try:
            # Serialize via httpx so the signed bytes are identical to the sent bytes.
            body_bytes = httpx.Request("POST", url, json=body_dict).content

            http_request = SignedRequest(
                url=url,
                method="POST",
                headers={"Content-Type": "application/json"},
                body=body_bytes,
            )
            if self._authenticator is not None:
                http_request = self._authenticator.authenticate(http_request)

            with httpx.Client() as client:
                response = client.post(
                    http_request.url,
                    content=http_request.body,
                    headers=http_request.headers,
                )

            if not 200 <= response.status_code < 300:
                try:
                    error_body = response.json()
                    message = error_body.get("message") or response.reason_phrase
                except Exception:  # noqa: BLE001 - non-JSON error body
                    message = response.reason_phrase

                # 409 Conflict: clientToken reused with different parameters
                if response.status_code == 409 and request.client_token:
                    raise IdempotencyConflictError(request.client_token, message)

                raise ValidationError(
                    f"Agent Pay authorization failed ({response.status_code}): {message}"
                )

            result = CreateAgentPaymentResponse.model_validate(response.json())
        except (ValidationError, IdempotencyConflictError):
            raise
        except Exception as error:  # noqa: BLE001 - normalize all other failures
            raise ValidationError(f"Failed to authorize payment with Agent Pay: {error}") from error

        return result

    def get_payment(self, payment_id: str) -> GetAgentPaymentResponse:
        """Retrieve a payment by ID.

        Maps to: GET /GetAgentPayment/{paymentId}

        :param payment_id: The payment ID (``awsmp-{UUID}``).
        :returns: Parsed ``GetAgentPaymentResponse``.
        :raises ValidationError: on authorization or request failure.
        """
        url = f"{self._base_url}/GetAgentPayment/{payment_id}"

        try:
            http_request = SignedRequest(
                url=url,
                method="GET",
                headers={},
            )
            if self._authenticator is not None:
                http_request = self._authenticator.authenticate(http_request)

            with httpx.Client() as client:
                response = client.get(
                    http_request.url,
                    headers=http_request.headers,
                )

            if not 200 <= response.status_code < 300:
                try:
                    error_body = response.json()
                    message = error_body.get("message") or response.reason_phrase
                except Exception:  # noqa: BLE001 - non-JSON error body
                    message = response.reason_phrase

                raise ValidationError(
                    f"Agent Pay request failed ({response.status_code}): {message}"
                )

            result = GetAgentPaymentResponse.model_validate(response.json())
        except ValidationError:
            raise
        except Exception as error:  # noqa: BLE001 - normalize all other failures
            raise ValidationError(f"Failed to get payment from Agent Pay: {error}") from error

        return result

    def list_payments(
        self,
        request: Optional[Union[ListAgentPaymentsRequest, dict[str, Any]]] = None,
    ) -> ListAgentPaymentsResponse:
        """List payments.

        Maps to: POST /ListAgentPayments

        :param request: Optional filters/pagination, as a
            :class:`~fiat_extension_x402.schemas.ListAgentPaymentsRequest` or an
            equivalent dict of camelCase keys.
        :returns: Parsed ``ListAgentPaymentsResponse``.
        :raises ValidationError: on authorization or request failure.
        """
        url = f"{self._base_url}/ListAgentPayments"
        if isinstance(request, ListAgentPaymentsRequest):
            body_dict: dict[str, Any] = request.model_dump(by_alias=True, exclude_none=True)
        else:
            body_dict = request or {}

        try:
            body_bytes = httpx.Request("POST", url, json=body_dict).content

            http_request = SignedRequest(
                url=url,
                method="POST",
                headers={"Content-Type": "application/json"},
                body=body_bytes,
            )
            if self._authenticator is not None:
                http_request = self._authenticator.authenticate(http_request)

            with httpx.Client() as client:
                response = client.post(
                    http_request.url,
                    content=http_request.body,
                    headers=http_request.headers,
                )

            if not 200 <= response.status_code < 300:
                try:
                    error_body = response.json()
                    message = error_body.get("message") or response.reason_phrase
                except Exception:  # noqa: BLE001 - non-JSON error body
                    message = response.reason_phrase

                raise ValidationError(
                    f"Agent Pay request failed ({response.status_code}): {message}"
                )

            result = ListAgentPaymentsResponse.model_validate(response.json())
        except ValidationError:
            raise
        except Exception as error:  # noqa: BLE001 - normalize all other failures
            raise ValidationError(f"Failed to list payments from Agent Pay: {error}") from error

        return result

    def verify_payment_token(self, token: str) -> PaymentTokenPayload:
        """Verify a payment token's signature against Agent Pay's public keys.

        Fetches Agent Pay's JWKS and checks the JWT signature, so callers who
        only need to confirm a token is genuine do not have to stand up a
        facilitator or supply a key themselves. For full payment verification —
        quote binding, amounts, expiry, DPoP — use
        :class:`~fiat_extension_x402.facilitator.AgentPayFacilitatorClient`.

        :param token: The payment token JWT to verify.
        :returns: The verified claims.
        :raises ValidationError: if the token is malformed, expired, unsigned by
            Agent Pay, or missing required claims.
        """
        try:
            with httpx.Client() as client:
                response = client.get(
                    f"{self._base_url}{WELL_KNOWN_JWKS_PATH}",
                    headers={"x-agentpay-key": AGENT_PAY_JWKS_ACCESS_KEY},
                )
            if not 200 <= response.status_code < 300:
                raise ValidationError(
                    f"Failed to fetch Agent Pay public keys ({response.status_code})"
                )

            jwks = pyjwt.PyJWKSet.from_dict(response.json())
            header = pyjwt.get_unverified_header(token)
            kid = header.get("kid")
            key = next((k for k in jwks.keys if k.key_id == kid), None)
            if key is None:
                raise ValidationError(f"No Agent Pay signing key matches kid: {kid}")

            # Expiry is enforced (aud is not — Agent Pay's audience is the
            # seller's service URL, which this method has no way to know).
            claims = pyjwt.decode(
                token,
                key.key,
                algorithms=ALLOWED_ALGORITHMS,
                options={"verify_exp": True, "verify_aud": False},
            )
            result = PaymentTokenPayload.model_validate(claims)
        except ValidationError:
            raise
        except Exception as error:  # noqa: BLE001 - normalize all other failures
            raise ValidationError(f"Failed to verify payment token: {error}") from error

        return result


__all__ = ["AgentPayClient", "AgentPayClientForClient", "DEFAULT_BASE_URL"]
