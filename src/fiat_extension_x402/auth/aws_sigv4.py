# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""AWS SigV4 authentication implementation.

Signs requests using AWS Signature Version 4 via ``botocore.auth.SigV4Auth`` — the
same signing logic used by the official AWS SDK clients.
"""

from __future__ import annotations

import os
from typing import Optional

from botocore.auth import SigV4Auth  # type: ignore[import-untyped]
from botocore.awsrequest import AWSRequest  # type: ignore[import-untyped]
from botocore.credentials import Credentials  # type: ignore[import-untyped]

from fiat_extension_x402.auth.errors import MissingCredentialsError
from fiat_extension_x402.auth.types import SignedRequest

# Default SigV4 service name (AWS Marketplace Agent Pay).
DEFAULT_SERVICE = "aws-marketplace"

# Default signing region.
DEFAULT_REGION = "us-east-1"


class AwsSigV4Authenticator:
    """Signs requests using AWS Signature Version 4.

    :param credentials: AWS credentials used for signing.
    :param region: Signing region. Defaults to ``us-east-1``.
    :param service: Signing service name. Defaults to ``aws-marketplace``.
    :raises MissingCredentialsError: if ``credentials`` is ``None`` or incomplete.
    """

    def __init__(
        self,
        credentials: Optional[Credentials],
        *,
        region: str = DEFAULT_REGION,
        service: str = DEFAULT_SERVICE,
    ) -> None:
        self._validate_credentials(credentials)
        self._credentials = credentials
        self._region = region
        self._service = service

    def authenticate(self, request: SignedRequest) -> SignedRequest:
        """Return a copy of ``request`` with SigV4 authentication headers added.

        The request's existing headers are included in the signature computation, so
        any header the server expects in ``SignedHeaders`` (e.g. ``Content-Type``)
        must be present on ``request`` before signing.
        """
        aws_request = AWSRequest(
            method=request.method,
            url=request.url,
            headers=dict(request.headers),
            data=request.body,
        )
        SigV4Auth(self._credentials, self._service, self._region).add_auth(aws_request)

        # After add_auth, aws_request.headers holds both the original headers and the
        # SigV4 auth headers, so no separate merge is needed.
        return SignedRequest(
            url=request.url,
            method=request.method,
            headers=dict(aws_request.headers),
            body=request.body,
        )

    @staticmethod
    def _validate_credentials(credentials: Optional[Credentials]) -> None:
        if credentials is None:
            raise MissingCredentialsError("awsSigV4", "credentials")
        if not getattr(credentials, "access_key", None):
            raise MissingCredentialsError("awsSigV4", "accessKeyId")
        if not getattr(credentials, "secret_key", None):
            raise MissingCredentialsError("awsSigV4", "secretAccessKey")


def create_env_credential_provider() -> Credentials:
    """Create AWS credentials from environment variables.

    Reads ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``, and optionally
    ``AWS_SESSION_TOKEN`` from the environment.

    :returns: A :class:`~botocore.credentials.Credentials` instance.
    :raises MissingCredentialsError: if required variables are not set.
    """
    access_key = os.environ.get("AWS_ACCESS_KEY_ID", "")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    session_token = os.environ.get("AWS_SESSION_TOKEN")

    if not access_key:
        raise MissingCredentialsError("awsSigV4", "AWS_ACCESS_KEY_ID")
    if not secret_key:
        raise MissingCredentialsError("awsSigV4", "AWS_SECRET_ACCESS_KEY")

    return Credentials(access_key, secret_key, session_token)


__all__ = [
    "DEFAULT_REGION",
    "DEFAULT_SERVICE",
    "AwsSigV4Authenticator",
    "create_env_credential_provider",
]
