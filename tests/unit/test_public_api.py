# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Public import-surface tests.

Asserts that the documented public API resolves from the package root. This is the
Python analog of the reference SDK's package-export test: it guards the symbols
listed in ``fiat_extension_x402.__all__`` rather than the reference's framework
scheme classes (which the Python SDK's flatter design does not expose).
"""

from __future__ import annotations

import fiat_extension_x402 as agent_pay


class TestPublicConstants:
    def test_constant_values(self) -> None:
        from fiat_extension_x402.constants import (
            AGENT_PAY_CAIP_FAMILY,
            AGENT_PAY_SCHEME,
            SETTLEMENT_CYCLES,
            SETTLEMENT_METHODS,
        )

        assert AGENT_PAY_SCHEME == "agent-pay"
        assert AGENT_PAY_CAIP_FAMILY == "aws:*"
        assert SETTLEMENT_METHODS is not None
        assert SETTLEMENT_CYCLES is not None


class TestPublicExports:
    def test_client_and_server(self) -> None:
        assert agent_pay.AgentPayClient is not None
        assert agent_pay.enhance_payment_requirements is not None

    def test_facilitator(self) -> None:
        assert agent_pay.AgentPayFacilitatorClient is not None
        assert agent_pay.InProcessFacilitatorClient is not None

    def test_signer_functions(self) -> None:
        assert agent_pay.to_service_agent_pay_signer is not None
        assert agent_pay.to_agent_pay_signer is not None

    def test_error_classes(self) -> None:
        assert agent_pay.AgentPayError is not None
        assert agent_pay.ValidationError is not None
        assert agent_pay.SignatureError is not None
        assert agent_pay.ExpiryError is not None
        assert agent_pay.MismatchError is not None
        assert agent_pay.DPoPError is not None

    def test_utility_functions(self) -> None:
        assert agent_pay.decode_quote_token is not None
        assert agent_pay.verify_quote_token is not None
        assert agent_pay.verify_payment_token is not None
        assert agent_pay.extract_quote_from_payment is not None
        assert agent_pay.generate_transaction_id is not None
        assert agent_pay.parse_money_to_decimal is not None

    def test_dpop_functions(self) -> None:
        assert agent_pay.generate_dpop_keypair is not None
        assert agent_pay.create_dpop_proof is not None
        assert agent_pay.verify_dpop_proof is not None
        assert agent_pay.compute_jwk_thumbprint is not None

    def test_auth_and_discovery(self) -> None:
        assert agent_pay.AwsSigV4Authenticator is not None
        assert agent_pay.create_authenticator is not None
        assert agent_pay.discover_agent_pay_endpoints is not None
        assert agent_pay.register_network is not None

    def test_all_exports_resolve(self) -> None:
        """Every name in __all__ resolves to a real attribute on the package."""
        for name in agent_pay.__all__:
            assert getattr(agent_pay, name) is not None, name
