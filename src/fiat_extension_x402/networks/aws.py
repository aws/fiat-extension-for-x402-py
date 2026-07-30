# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""AWS-preconfigured Agent Pay schemes.

Thin subclasses that pin the Agent Pay endpoint so callers integrating with AWS
Marketplace do not have to supply it. Behaviour is otherwise identical to the
base schemes.

    from x402 import x402ClientSync
    from fiat_extension_x402.networks import AgentPayAWSClientScheme

    client = x402ClientSync()
    client.register("aws:base", AgentPayAWSClientScheme(agent_pay_id="YOUR_ACCOUNT_ID"))
"""

from __future__ import annotations

from typing import Any, Optional

from botocore.credentials import Credentials  # type: ignore[import-untyped]

from fiat_extension_x402.auth import Authenticator
from fiat_extension_x402.client_scheme import AgentPayClientScheme, AgentPayConfig
from fiat_extension_x402.constants import DEFAULT_AGENT_PAY_BASE_URL
from fiat_extension_x402.facilitator_scheme import AgentPayFacilitatorScheme
from fiat_extension_x402.server_scheme import AgentPayServerScheme
from fiat_extension_x402.signers.protocol import ServiceAgentPaySigner


class AgentPayAWSClientScheme(AgentPayClientScheme):
    """Buyer scheme pinned to the AWS Marketplace Agent Pay endpoint.

    :param agent_pay_id: Agent Pay identifier for this buyer.
    :param authenticator: Authenticator used to sign Agent Pay requests.
    :param credentials: AWS credentials for SigV4 signing (mutually exclusive
        with ``authenticator``).
    """

    def __init__(
        self,
        *,
        agent_pay_id: str,
        authenticator: Optional[Authenticator] = None,
        credentials: Optional[Credentials] = None,
    ) -> None:
        super().__init__(
            agent_pay_id=agent_pay_id,
            agent_pay=AgentPayConfig(
                base_url=DEFAULT_AGENT_PAY_BASE_URL,
                authenticator=authenticator,
                credentials=credentials,
            ),
        )


class AgentPayAWSServerScheme(AgentPayServerScheme):
    """Seller scheme for AWS Marketplace Agent Pay.

    :param signer: Signer that mints quote tokens.
    """

    def __init__(self, *, signer: ServiceAgentPaySigner) -> None:
        super().__init__(signer=signer)


class AgentPayAWSFacilitatorScheme(AgentPayFacilitatorScheme):
    """Verifier scheme pinned to the AWS Marketplace Agent Pay endpoint.

    :param agent_pay_id: Agent Pay identifier advertised in supported-kinds.
        Defaults to ``'aws-agent-pay'``.
    :param verify_options: Default options forwarded to every ``verify`` call.
    """

    def __init__(
        self,
        *,
        agent_pay_id: str = "aws-agent-pay",
        verify_options: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(agent_pay_id=agent_pay_id, verify_options=verify_options)


__all__ = [
    "AgentPayAWSClientScheme",
    "AgentPayAWSFacilitatorScheme",
    "AgentPayAWSServerScheme",
]
