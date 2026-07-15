# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Default Agent Pay client implementation.

Handles HTTP communication with the AWS Marketplace Agent Pay Service.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx
from botocore.credentials import Credentials  # type: ignore[import-untyped]

from fiat_extension_x402.auth import Authenticator, AwsSigV4Authenticator, SignedRequest
from fiat_extension_x402.exceptions import IdempotencyConflictError, ValidationError
from fiat_extension_x402.schemas import (
    CreateAgentPaymentRequest,
    CreateAgentPaymentResponse,
    GetAgentPaymentResponse,
    ListAgentPaymentsResponse,
)

# Default Agent Pay endpoint (production).
DEFAULT_BASE_URL = "https://prod.agentpay.marketplace.aws.dev"


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

    def list_payments(self, request: Optional[dict[str, Any]] = None) -> ListAgentPaymentsResponse:
        """List payments.

        Maps to: POST /ListAgentPayments

        :param request: Optional request body with filters/pagination.
        :returns: Parsed ``ListAgentPaymentsResponse``.
        :raises ValidationError: on authorization or request failure.
        """
        url = f"{self._base_url}/ListAgentPayments"
        body_dict: dict[str, Any] = request or {}

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


__all__ = ["AgentPayClient", "DEFAULT_BASE_URL"]
