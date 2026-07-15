# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the live Agent Pay end-to-end suite.

Every fixture here is environment-gated: when the required configuration is not
present, the dependent tests are skipped (never failed), so the suite is a no-op
in environments without live credentials. No real account IDs or endpoints are
hard-coded — they are supplied entirely through environment variables:

* ``AGENTPAY_URL`` — Agent Pay service base URL.
* ``AGENTPAY_SELLER_KMS_KEY_ARN`` — seller KMS key ARN (ECC_NIST_P384), used only
  by the negative-path tests that forge bad claims.
* ``AGENTPAY_SELLER_REGION`` — region of the seller KMS key (default ``us-east-1``).
* ``AGENTPAY_SELLER_SERVICE_URL`` — seller service URL. This endpoint returns a
  real HTTP 402 with a service-registered, signed quote token (the authoritative
  quote source for the happy-path tests) and exposes the seller JWKS.
* ``AGENTPAY_SELLER_PROFILE`` — *optional* AWS profile for the seller account that
  owns the KMS key. The buyer and seller are different accounts, so the KMS client
  used for signing must be built from the seller's credentials, not the ambient
  (buyer) profile. When unset, the ambient profile is used (kms:Sign will be
  denied unless the ambient identity owns the key).
* Buyer AWS credentials are read from the ambient environment via the standard
  ``AWS_*`` variables / profile (SigV4), so an AWS profile must be active.

Two realities drive the design:

1. The reference test seller signs quotes with a self-hosted key, so the happy
   path sources its quote from the live 402 endpoint rather than minting one via
   KMS (a KMS-minted quote would carry an unregistered key and be rejected).
2. The shared test seller/product is registered only in *prod*. Against any stage
   that does not recognise it, ``agent_pay_environment_ready`` skips (does not
   fail) the live-acceptance tests with a clear reason.

Run the suite with::

    pytest -m e2e

(without ``-m e2e`` these tests are deselected by the project's ``addopts``).
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

import pytest


@dataclass(frozen=True)
class AgentPayConfig:
    """Resolved live-service configuration sourced from the environment."""

    agent_pay_url: str
    seller_kms_key_arn: str
    seller_region: str
    seller_service_url: str
    seller_profile: Optional[str]


def _env(name: str) -> Optional[str]:
    value = os.environ.get(name)
    return value if value else None


@pytest.fixture(scope="session")
def agent_pay_config() -> AgentPayConfig:
    """Resolve live-service configuration from the environment or skip the suite.

    Skips (does not fail) when any required variable is unset so the suite is
    inert in CI / open-source environments without live access.
    """
    agent_pay_url = _env("AGENTPAY_URL")
    seller_kms_key_arn = _env("AGENTPAY_SELLER_KMS_KEY_ARN")
    seller_service_url = _env("AGENTPAY_SELLER_SERVICE_URL")

    missing = [
        name
        for name, value in (
            ("AGENTPAY_URL", agent_pay_url),
            ("AGENTPAY_SELLER_KMS_KEY_ARN", seller_kms_key_arn),
            ("AGENTPAY_SELLER_SERVICE_URL", seller_service_url),
        )
        if not value
    ]
    if missing:
        pytest.skip(f"Agent Pay E2E disabled — unset env vars: {', '.join(missing)}")

    assert agent_pay_url is not None
    assert seller_kms_key_arn is not None
    assert seller_service_url is not None
    return AgentPayConfig(
        agent_pay_url=agent_pay_url,
        seller_kms_key_arn=seller_kms_key_arn,
        seller_region=os.environ.get("AGENTPAY_SELLER_REGION", "us-east-1"),
        seller_service_url=seller_service_url,
        seller_profile=_env("AGENTPAY_SELLER_PROFILE"),
    )


@pytest.fixture(scope="session")
def buyer_credentials() -> object:
    """Resolve buyer AWS credentials from the ambient environment/profile.

    Skips when no credentials can be resolved (e.g. no active AWS profile).
    """
    import botocore.session  # type: ignore[import-untyped]

    creds = botocore.session.Session().get_credentials()
    if creds is None:
        pytest.skip("Agent Pay E2E disabled — no ambient AWS credentials for the buyer")
    return creds.get_frozen_credentials()


def _build_buyer_client(agent_pay_config: AgentPayConfig, buyer_credentials: object) -> Any:
    """Construct an ``AgentPayClient`` pointed at the configured service URL."""
    from botocore.credentials import Credentials  # type: ignore[import-untyped]

    from fiat_extension_x402 import AgentPayClient

    frozen = buyer_credentials
    credentials = Credentials(
        access_key=frozen.access_key,  # type: ignore[attr-defined]
        secret_key=frozen.secret_key,  # type: ignore[attr-defined]
        token=getattr(frozen, "token", None),
    )
    return AgentPayClient(base_url=agent_pay_config.agent_pay_url, credentials=credentials)


@pytest.fixture
def buyer_client(agent_pay_config: AgentPayConfig, buyer_credentials: object) -> object:
    """An ``AgentPayClient`` pointed at the service, signing with buyer SigV4 creds."""
    return _build_buyer_client(agent_pay_config, buyer_credentials)


@pytest.fixture
def seller_signer(agent_pay_config: AgentPayConfig) -> object:
    """A KMS-backed ``ServiceAgentPaySigner`` for minting forged quote tokens.

    Used only by the negative-path tests (expired / missing-issuer). The KMS
    client is built from the seller account's profile (``AGENTPAY_SELLER_PROFILE``)
    because the signing key lives in a different account from the buyer; signing
    with the ambient buyer profile would be denied (``kms:Sign``).
    """
    import boto3  # type: ignore[import-untyped]

    from fiat_extension_x402 import KmsSignerConfig, create_kms_signer

    if agent_pay_config.seller_profile:
        session = boto3.Session(profile_name=agent_pay_config.seller_profile)
    else:
        session = boto3.Session()
    kms_client = session.client("kms", region_name=agent_pay_config.seller_region)

    return create_kms_signer(
        KmsSignerConfig(
            key_arn=agent_pay_config.seller_kms_key_arn,
            region=agent_pay_config.seller_region,
            service_url=agent_pay_config.seller_service_url,
            _kms_client=kms_client,
        )
    )


@pytest.fixture
def quote_source(agent_pay_config: AgentPayConfig) -> Callable[[], tuple[dict[str, Any], str]]:
    """Return a callable that fetches a fresh, service-registered 402 quote.

    Each call performs a live GET against the seller endpoint and returns
    ``(requirements, quote_token)`` parsed from the 402 ``accepts[0]`` offer. This
    is the authoritative quote source: the token is signed by the seller's real,
    registered key, so the Agent Pay service accepts it. Skips if the endpoint
    does not return a usable 402.
    """
    import httpx

    def _fetch() -> tuple[dict[str, Any], str]:
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.get(agent_pay_config.seller_service_url)
        except httpx.HTTPError as exc:  # pragma: no cover - network failure path
            pytest.skip(f"Seller endpoint unreachable: {exc}")

        if response.status_code != 402:
            pytest.skip(
                f"Seller endpoint did not return HTTP 402 "
                f"(got {response.status_code}) — no quote to pay"
            )

        accepts = (response.json() or {}).get("accepts") or []
        if not accepts:
            pytest.skip("Seller 402 response carried no 'accepts' offers")

        offer = accepts[0]
        extra = offer.get("extra") or {}
        quote_token = extra.get("quoteToken")
        if not quote_token:
            pytest.skip("Seller 402 offer carried no quoteToken")

        requirements: dict[str, Any] = {
            "amount": offer["amount"],
            "asset": offer["asset"],
            "network": offer["network"],
        }
        return requirements, quote_token

    return _fetch


@pytest.fixture(scope="session")
def agent_pay_environment_ready(
    agent_pay_config: AgentPayConfig, buyer_credentials: object
) -> bool:
    """Probe once that this Agent Pay stage accepts the test seller's quotes.

    Performs a single real ``CreateAgentPayment`` with a live quote. On success
    the stage recognises the seller and the live-acceptance tests run. If the
    stage rejects a valid quote — typically because the test seller is not
    registered in this stage — the dependent tests are *skipped*, not failed,
    with a clear reason. This keeps the suite green when pointed at a stage that
    lacks the shared test fixtures.
    """
    import httpx

    from fiat_extension_x402.exceptions import ValidationError
    from fiat_extension_x402.schemas import CreateAgentPaymentRequest

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.get(agent_pay_config.seller_service_url)
    except httpx.HTTPError as exc:  # pragma: no cover - network failure path
        pytest.skip(f"Seller endpoint unreachable during readiness probe: {exc}")

    if response.status_code != 402:
        pytest.skip(f"Readiness probe: seller endpoint returned {response.status_code}, not 402")

    accepts = (response.json() or {}).get("accepts") or []
    if not accepts or not (accepts[0].get("extra") or {}).get("quoteToken"):
        pytest.skip("Readiness probe: seller 402 carried no quoteToken")

    quote_token = accepts[0]["extra"]["quoteToken"]
    client_obj = _build_buyer_client(agent_pay_config, buyer_credentials)
    try:
        client_obj.create_payment(
            CreateAgentPaymentRequest(quote_token=quote_token, client_token=str(uuid.uuid4()))
        )
    except ValidationError as exc:
        pytest.skip(
            f"Agent Pay stage {agent_pay_config.agent_pay_url} rejected a valid test-seller quote "
            f"(seller likely not registered in this stage): {exc}"
        )
    return True


@pytest.fixture
def facilitator() -> object:
    """An ``AgentPayFacilitatorClient`` for seller-side verify/settle against the JWKS."""
    from fiat_extension_x402 import AgentPayFacilitatorClient

    return AgentPayFacilitatorClient()
