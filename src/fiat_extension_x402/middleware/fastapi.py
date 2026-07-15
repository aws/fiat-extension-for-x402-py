# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""FastAPI middleware for Agent Pay x402 payment protection.

Provides plug-and-play FastAPI middleware that protects routes with Agent Pay
payments. Handles the full lifecycle: 402 generation, payment verification,
and settlement.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from fiat_extension_x402.builders.resource_server_builder import (
    AgentPayResourceServer,
    AgentPayResourceServerOptions,
    InitializeOptions,
    create_agent_pay_resource_server,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.middleware.types import AgentPayRouteConfig, PaymentInfo
from fiat_extension_x402.signers.protocol import ServiceAgentPaySigner

_logger = logging.getLogger(__name__)


@dataclass
class AgentPayFastAPIMiddlewareConfig:
    """Middleware configuration for FastAPI.

    :param agent_pay_base_url: Agent Pay provider base URL.
    :param agent_pay_id: Agent Pay ID for the facilitator.
    :param signer: Service signer for quote tokens.
    :param service_url: Service URL (used as issuer in quote tokens).
    :param networks: Networks to register for Agent Pay.
    :param routes: Route payment configurations (``"METHOD /path"`` -> config).
    :param disable_default_fallback: Disable default facilitator fallback.
    :param on_payment_verified: Async hook called after successful payment verification.
    :param on_payment_settled: Async hook called after successful settlement.
    :param on_error: Custom error handler.
    """

    agent_pay_base_url: str
    agent_pay_id: str
    signer: ServiceAgentPaySigner
    service_url: str
    networks: list[str]
    routes: dict[str, AgentPayRouteConfig]
    disable_default_fallback: bool = False
    on_payment_verified: Optional[Callable[[Request, PaymentInfo], Awaitable[None]]] = None
    on_payment_settled: Optional[Callable[[Request, PaymentInfo, str], Awaitable[None]]] = None
    on_error: Optional[Callable[[Exception, Request], Response]] = None


@dataclass
class _CompiledRoute:
    """Internal compiled route for matching."""

    method: str  # uppercase or '*'
    regex: re.Pattern[str]
    config: AgentPayRouteConfig


def _compile_routes(routes: dict[str, AgentPayRouteConfig]) -> list[_CompiledRoute]:
    """Compile route patterns into regex matchers."""
    compiled: list[_CompiledRoute] = []
    for pattern, config in routes.items():
        parts = pattern.strip().split()
        if len(parts) == 2:
            method = parts[0].upper()
            path = parts[1]
        elif len(parts) == 1:
            method = "*"
            path = parts[0]
        else:
            raise ValidationError(
                f'Invalid route pattern: "{pattern}". Expected "METHOD /path" or "/path".'
            )

        regex_str = path.replace("*", ".*")
        regex_str = re.sub(r":([^/]+)", r"([^/]+)", regex_str)
        compiled.append(
            _CompiledRoute(method=method, regex=re.compile(f"^{regex_str}$"), config=config)
        )
    return compiled


def _match_route(
    compiled_routes: list[_CompiledRoute], method: str, path: str
) -> Optional[AgentPayRouteConfig]:
    """Match an incoming request to a route config."""
    for route in compiled_routes:
        if route.method != "*" and route.method != method.upper():
            continue
        if route.regex.match(path):
            return route.config
    return None


def _extract_payment_payload(req: Request) -> Optional[dict[str, Any]]:
    """Extract payment payload from request headers."""
    auth_header = req.headers.get("authorization", "")
    if auth_header.startswith("x402 "):
        try:
            data = auth_header[5:]
            return json.loads(base64.b64decode(data))  # type: ignore[no-any-return]
        except Exception:
            return None

    payment_header = req.headers.get("x-payment")
    if payment_header:
        try:
            return json.loads(base64.b64decode(payment_header))  # type: ignore[no-any-return]
        except Exception:
            return None

    sig_header = req.headers.get("payment-signature")
    if sig_header:
        try:
            return json.loads(base64.b64decode(sig_header))  # type: ignore[no-any-return]
        except Exception:
            return None

    return None


def agent_pay_fastapi_middleware(
    config: AgentPayFastAPIMiddlewareConfig,
) -> Callable[[FastAPI], None]:
    """Create FastAPI middleware that protects routes with Agent Pay payments.

    The middleware intercepts requests to configured routes, returns 402 if no
    payment is present, verifies payments, settles them, and then allows the
    request to proceed. After verification, ``request.state.agent_pay_payment``
    contains the payment details.

    :param config: Middleware configuration.
    :returns: A function that registers the middleware on a FastAPI app.
    :raises ValidationError: if configuration is invalid.
    """
    if not config.networks:
        raise ValidationError("networks must be a non-empty array")
    if not config.routes:
        raise ValidationError("routes must be a non-empty object")

    compiled_routes = _compile_routes(config.routes)

    # Lazy-initialize the resource server.
    _server: Optional[AgentPayResourceServer] = None

    def _get_server() -> AgentPayResourceServer:
        nonlocal _server
        if _server is None:
            ap_server = create_agent_pay_resource_server(
                AgentPayResourceServerOptions(
                    agent_pay_base_url=config.agent_pay_base_url,
                    agent_pay_id=config.agent_pay_id,
                    signer=config.signer,
                    service_url=config.service_url,
                )
            )
            for network in config.networks:
                ap_server.register_network(network)
            ap_server.initialize(
                InitializeOptions(disable_default_fallback=config.disable_default_fallback)
            )
            _server = ap_server
        return _server

    def _send_error(status: int, message: str, details: Optional[str] = None) -> JSONResponse:
        body: dict[str, Any] = {"error": message}
        if details:
            body["details"] = details
        return JSONResponse(content=body, status_code=status)

    def init_app(app: FastAPI) -> None:
        """Register the middleware on a FastAPI application."""

        @app.middleware("http")
        async def _agent_pay_middleware(
            request: Request,
            call_next: Callable[[Request], Awaitable[Response]],
        ) -> Response:
            route_config = _match_route(compiled_routes, request.method, request.url.path)

            # Not a protected route — pass through.
            if route_config is None:
                return await call_next(request)

            try:
                server = _get_server()
                payment_payload = _extract_payment_payload(request)

                if payment_payload is None:
                    # No payment — return 402.
                    requirements = await server.build_payment_requirements(
                        network=route_config.network,
                        pay_to=route_config.pay_to,
                        price=route_config.price,
                        asset=route_config.asset,
                        extra={
                            **(
                                {"description": route_config.description}
                                if route_config.description
                                else {}
                            ),
                            **(
                                {"dimensions": route_config.dimensions}
                                if route_config.dimensions
                                else {}
                            ),
                            **(route_config.extra or {}),
                        },
                    )

                    payment_required = {
                        "x402Version": 1,
                        "accepts": [requirements],
                        "url": f"{config.service_url}{request.url.path}",
                        "description": (
                            route_config.description or f"Access to {request.url.path}"
                        ),
                        "mimeType": route_config.mime_type or "application/json",
                    }

                    accepts_base64 = base64.b64encode(
                        json.dumps(payment_required).encode()
                    ).decode()

                    return JSONResponse(
                        content=payment_required,
                        status_code=402,
                        headers={
                            "WWW-Authenticate": (f'x402 version=1, accepts="{accepts_base64}"'),
                            "PAYMENT-REQUIRED": accepts_base64,
                        },
                    )

                # Payment present — verify.
                accepted = payment_payload.get("accepted")
                if not accepted:
                    return _send_error(
                        400,
                        "Invalid payment",
                        "Missing accepted requirements in payment payload",
                    )

                extra = accepted.get("extra", {})
                expected_quote_token = extra.get("quoteToken", "")
                ap_payload = payment_payload.get("payload", {})
                payment_token = ap_payload.get("paymentToken", "")

                verify_result = server.facilitator.verify(
                    payment_token, expected_quote_token, accepted
                )

                if not verify_result.is_valid:
                    return _send_error(
                        402, "Payment verification failed", verify_result.invalid_message
                    )

                # Build payment info.
                payment = PaymentInfo(
                    payer=verify_result.payer or "unknown",
                    transaction_id=ap_payload.get("transactionId", ""),
                    network=accepted.get("network", ""),
                    amount=accepted.get("amount", ""),
                    asset=accepted.get("asset", ""),
                )

                # Call on_payment_verified hook.
                if config.on_payment_verified:
                    await config.on_payment_verified(request, payment)

                # Agent Pay auto-captures — no settle call needed.
                if config.on_payment_settled:
                    await config.on_payment_settled(request, payment, payment.transaction_id)

                # Attach payment info to request state.
                request.state.agent_pay_payment = payment

                # Call the actual route handler.
                response = await call_next(request)

                # Add payment response header.
                settle_response = {
                    "success": True,
                    "network": payment.network,
                    "transaction": payment.transaction_id,
                }
                response.headers["PAYMENT-RESPONSE"] = base64.b64encode(
                    json.dumps(settle_response).encode()
                ).decode()

                return response

            except Exception as exc:
                if config.on_error:
                    return config.on_error(exc, request)
                # Log the details server-side; never echo them to the client.
                _logger.exception("Unhandled error while processing payment")
                return _send_error(500, "Internal server error")

    return init_app


__all__ = [
    "AgentPayFastAPIMiddlewareConfig",
    "AgentPayRouteConfig",
    "PaymentInfo",
    "agent_pay_fastapi_middleware",
]
