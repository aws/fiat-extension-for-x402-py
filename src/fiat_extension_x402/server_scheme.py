# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Agent Pay server scheme — the seller-side x402 payment mechanism.

In Agent Pay, the "server" role is played by the resource service (the seller),
which answers an unpaid request with HTTP 402 and a signed quote token.

This module adapts the SDK's quote-token generation to the x402 core server
contract (:class:`x402.interfaces.SchemeNetworkServer`), so a seller can build
402 responses through the generic framework::

    from x402 import x402ResourceServerSync
    from x402.schemas import ResourceConfig

    server = x402ResourceServerSync(facilitator_client)
    server.register("aws:base", AgentPayServerScheme(signer=my_signer))
    server.initialize()

    requirements = server.build_payment_requirements(
        ResourceConfig(scheme="agent-pay", network="aws:base",
                       pay_to="your-seller-id", price="0.50")
    )

The standalone :func:`~fiat_extension_x402.server.enhance_payment_requirements`
function remains available and unchanged; this scheme delegates to it, so both
paths emit identical quote tokens.
"""

from __future__ import annotations

from typing import Any

from x402.schemas import AssetAmount, PaymentRequirements, Price, SupportedKind

from fiat_extension_x402._sync import run_coroutine_sync
from fiat_extension_x402.constants import AGENT_PAY_CAIP_FAMILY, AGENT_PAY_SCHEME
from fiat_extension_x402.server.scheme import enhance_payment_requirements
from fiat_extension_x402.signers.protocol import ServiceAgentPaySigner
from fiat_extension_x402.utils import parse_money_to_decimal


class AgentPayServerScheme:
    """Agent Pay seller scheme satisfying x402 core's ``SchemeNetworkServer``.

    Converts a user-friendly price into an Agent Pay amount/asset pair and
    enhances payment requirements with a signed quote token.

    :param signer: Signer that mints quote tokens. Its ``get_service_url()``
        becomes the quote token's ``iss`` claim and must be non-empty.
    """

    def __init__(self, *, signer: ServiceAgentPaySigner) -> None:
        self._signer = signer

    @property
    def scheme(self) -> str:
        """x402 scheme identifier handled by this server (``agent-pay``)."""
        return AGENT_PAY_SCHEME

    @property
    def caip_family(self) -> str:
        """CAIP family this scheme serves (``aws:*``)."""
        return AGENT_PAY_CAIP_FAMILY

    @property
    def signer(self) -> ServiceAgentPaySigner:
        """The configured quote-token signer."""
        return self._signer

    def parse_price(self, price: Price | dict[str, Any], network: str) -> AssetAmount:
        """Normalise a price into an Agent Pay ``AssetAmount``.

        Agent Pay prices are fiat decimal strings (``"0.50"``) with an ISO 4217
        asset (``"iso4217:USD"``) — there is no atomic-unit conversion, unlike
        the on-chain schemes.

        :param price: ``"$1.50"``, ``"1.50 USD"``, ``1.50``, an
            already-normalised ``AssetAmount``, or an equivalent dict.
        :param network: Target network. Unused — Agent Pay pricing is
            network-independent — but required by the x402 contract.
        :returns: The normalised amount and ISO 4217 asset.
        """
        if isinstance(price, AssetAmount):
            return price
        # A dict that already looks like an AssetAmount passes through too.
        if isinstance(price, dict):
            return AssetAmount.model_validate(price)

        parsed = parse_money_to_decimal(price)
        return AssetAmount(
            amount=str(parsed["amount"]),
            asset=f"iso4217:{parsed['currency']}",
            extra={},
        )

    def enhance_payment_requirements(
        self,
        requirements: PaymentRequirements,
        supported_kind: SupportedKind | None = None,
        extensions: list[str] | None = None,
    ) -> PaymentRequirements:
        """Sign a quote token and embed it in the payment requirements.

        Delegates to the standalone
        :func:`~fiat_extension_x402.server.enhance_payment_requirements`, so the
        framework path and the direct path produce identical quote tokens. The
        returned requirements carry the sentinel ``payTo`` and a
        ``maxTimeoutSeconds`` derived from the signed quote — the token is the
        authoritative source for both.

        :param requirements: Base x402 payment requirements.
        :param supported_kind: The facilitator's supported kind. Unused by Agent
            Pay; accepted for x402 contract compatibility.
        :param extensions: Enabled extension keys. Unused by Agent Pay.
        :returns: Enhanced requirements with ``extra.quoteToken`` set.
        :raises ValidationError: if the signer's service URL (issuer) is empty.
        """
        base: dict[str, Any] = requirements.model_dump(by_alias=True, exclude_none=True)
        # The signer is async (KMS offloads its blocking call to a thread), but
        # x402 core calls this method synchronously.
        enhanced = run_coroutine_sync(enhance_payment_requirements(base, self._signer))
        return PaymentRequirements.model_validate(enhanced)


__all__ = ["AgentPayServerScheme"]
