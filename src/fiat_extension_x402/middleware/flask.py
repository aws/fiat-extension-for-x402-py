# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Flask middleware for Agent Pay x402 payment protection.

Provides plug-and-play Flask middleware that protects routes with Agent Pay
payments. Handles the full lifecycle: 402 generation, payment verification,
and settlement.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

from flask import Flask, Request, Response, g, request

from fiat_extension_x402.builders.resource_server_builder import (
    AgentPayResourceServer,
    AgentPayResourceServerOptions,
    InitializeOptions,
    create_agent_pay_resource_server,
)
from fiat_extension_x402.exceptions import ValidationError
from fiat_extension_x402.middleware.types import AgentPayRouteConfig, PaymentInfo
from fiat_extension_x402.signers.protocol import ServiceAgentPaySigner


@dataclass
class AgentPayMiddlewareConfig:
    """Middleware configuration.

    :param agent_pay_base_url: Agent Pay provider base URL.
    :param agent_pay_id: Agent Pay ID for the facilitator.
    :param signer: Service signer for quote tokens.
    :param service_url: Service URL (used as issuer in quote tokens).
    :param networks: Networks to register for Agent Pay.
    :param routes: Route payment configurations (``"METHOD /path"`` -> config).
    :param disable_default_fallback: Disable default facilitator fallback.
    :param on_payment_verified: Hook called after successful payment verification.
    :param on_payment_settled: Hook called after successful settlement.
    :param on_error: Custom error handler.
    """

    agent_pay_base_url: str
    agent_pay_id: str
    signer: ServiceAgentPaySigner
    service_url: str
    networks: list[str]
    routes: dict[str, AgentPayRouteConfig]
    disable_default_fallback: bool = False
    on_payment_verified: Optional[Callable[[Request, PaymentInfo], None]] = None
    on_payment_settled: Optional[Callable[[Request, PaymentInfo, str], None]] = None
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

        # Convert path to regex: /api/* -> /api/.*, /api/:id -> /api/[^/]+
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
    # Check x402 Authorization header: "x402 <base64>"
    auth_header = req.headers.get("authorization", "")
    if auth_header.startswith("x402 "):
        try:
            data = auth_header[5:]
            return json.loads(base64.b64decode(data))  # type: ignore[no-any-return]
        except Exception:
            return None

    # Check X-Payment header
    payment_header = req.headers.get("x-payment")
    if payment_header:
        try:
            return json.loads(base64.b64decode(payment_header))  # type: ignore[no-any-return]
        except Exception:
            return None

    # Check payment-signature header
    sig_header = req.headers.get("payment-signature")
    if sig_header:
        try:
            return json.loads(base64.b64decode(sig_header))  # type: ignore[no-any-return]
        except Exception:
            return None

    return None


def _run_async(coro: Any) -> Any:
    """Run an async coroutine synchronously.

    Used to drive the async quote-signing path from Flask's synchronous request
    handling. When called outside any event loop (the normal Flask case), runs the
    coroutine directly; when called from within a running loop, offloads it to a
    worker thread so it does not deadlock.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No running loop — the common synchronous Flask case.
        return asyncio.run(coro)

    # A loop is already running in this thread; run the coroutine in a worker
    # thread so we don't block or reuse the running loop.
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(asyncio.run, coro)
        return future.result()


def agent_pay_middleware(config: AgentPayMiddlewareConfig) -> Callable[[Flask], None]:
    """Create Flask middleware that protects routes with Agent Pay payments.

    The middleware intercepts requests to configured routes, returns 402 if no
    payment is present, verifies payments, settles them, and then allows the
    request to proceed. After verification, ``g.agent_pay_payment`` contains
    the payment details.

    :param config: Middleware configuration.
    :returns: A function that registers the middleware on a Flask app.
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

    def _send_error(status: int, message: str, details: Optional[str] = None) -> Response:
        body: dict[str, Any] = {"error": message}
        if details:
            body["details"] = details
        return Response(
            json.dumps(body),
            status=status,
            content_type="application/json",
        )

    def init_app(app: Flask) -> None:
        """Register the middleware on a Flask application."""

        @app.before_request
        def _agent_pay_before_request() -> Optional[Response]:
            route_config = _match_route(compiled_routes, request.method, request.path)

            # Not a protected route — pass through.
            if route_config is None:
                return None

            try:
                server = _get_server()
                payment_payload = _extract_payment_payload(request)

                if payment_payload is None:
                    # No payment — return 402.
                    requirements = _run_async(
                        server.build_payment_requirements(
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
                    )

                    payment_required = {
                        "x402Version": 1,
                        "accepts": [requirements],
                        "url": f"{config.service_url}{request.path}",
                        "description": route_config.description or f"Access to {request.path}",
                        "mimeType": route_config.mime_type or "application/json",
                    }

                    accepts_base64 = base64.b64encode(
                        json.dumps(payment_required).encode()
                    ).decode()

                    resp = Response(
                        json.dumps(payment_required),
                        status=402,
                        content_type="application/json",
                    )
                    resp.headers["WWW-Authenticate"] = f'x402 version=1, accepts="{accepts_base64}"'
                    resp.headers["PAYMENT-REQUIRED"] = accepts_base64
                    return resp

                # Payment present — verify.
                accepted = payment_payload.get("accepted")
                if not accepted:
                    return _send_error(
                        400,
                        "Invalid payment",
                        "Missing accepted requirements in payment payload",
                    )

                # Extract quote token from requirements for verification.
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
                    config.on_payment_verified(request, payment)

                # Agent Pay auto-captures — no settle call needed.
                if config.on_payment_settled:
                    config.on_payment_settled(request, payment, payment.transaction_id)

                # Store settle response for after_request handler.
                g._agent_pay_settle_response = {
                    "success": True,
                    "network": payment.network,
                    "transaction": payment.transaction_id,
                }

                # Attach payment info to request context.
                g.agent_pay_payment = payment
                return None

            except Exception as exc:
                if config.on_error:
                    return config.on_error(exc, request)
                return _send_error(
                    500,
                    "Internal server error",
                    str(exc) if str(exc) else "Unknown error",
                )

        @app.after_request
        def _agent_pay_after_request(response: Response) -> Response:
            settle_response = getattr(g, "_agent_pay_settle_response", None)
            if settle_response is not None:
                response.headers["PAYMENT-RESPONSE"] = base64.b64encode(
                    json.dumps(settle_response).encode()
                ).decode()
            return response

    return init_app


__all__ = [
    "AgentPayMiddlewareConfig",
    "AgentPayRouteConfig",
    "PaymentInfo",
    "agent_pay_middleware",
]
