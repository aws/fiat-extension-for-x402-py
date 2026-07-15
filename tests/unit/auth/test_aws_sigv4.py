# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the AWS SigV4 authenticator."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from botocore.credentials import Credentials  # type: ignore[import-untyped]

from fiat_extension_x402.auth import (
    AwsSigV4Authenticator,
    MissingCredentialsError,
    SignedRequest,
    create_env_credential_provider,
)
from fiat_extension_x402.auth.aws_sigv4 import DEFAULT_REGION, DEFAULT_SERVICE

_URL = "https://test.agentpay.example.com/CreateAgentPayment"

_FULL_CREDENTIALS = Credentials(
    access_key="AKIAIOSFODNN7EXAMPLE",
    secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    token="FwoGZXIvYXdzEBYaDHqa0AP1",
)

_NO_TOKEN_CREDENTIALS = Credentials(
    access_key="AKIAIOSFODNN7EXAMPLE",
    secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)


def _request() -> SignedRequest:
    return SignedRequest(url=_URL, method="POST", body=b'{"quoteToken":"eyJ"}')


class TestDefaults:
    def test_default_service_and_region(self) -> None:
        assert DEFAULT_SERVICE == "aws-marketplace"
        assert DEFAULT_REGION == "us-east-1"


class TestSigning:
    def test_adds_authorization_header(self) -> None:
        auth = AwsSigV4Authenticator(_FULL_CREDENTIALS)
        signed = auth.authenticate(_request())

        headers = {k.lower(): v for k, v in signed.headers.items()}
        assert headers["authorization"].startswith("AWS4-HMAC-SHA256")
        assert "x-amz-date" in headers

    def test_signature_references_service_and_region(self) -> None:
        auth = AwsSigV4Authenticator(_FULL_CREDENTIALS)
        signed = auth.authenticate(_request())

        auth_header = {k.lower(): v for k, v in signed.headers.items()}["authorization"]
        assert DEFAULT_SERVICE in auth_header
        assert DEFAULT_REGION in auth_header

    def test_includes_security_token_when_present(self) -> None:
        auth = AwsSigV4Authenticator(_FULL_CREDENTIALS)
        signed = auth.authenticate(_request())

        headers = {k.lower(): v for k, v in signed.headers.items()}
        assert "x-amz-security-token" in headers

    def test_omits_security_token_when_absent(self) -> None:
        auth = AwsSigV4Authenticator(_NO_TOKEN_CREDENTIALS)
        signed = auth.authenticate(_request())

        headers = {k.lower(): v for k, v in signed.headers.items()}
        assert "x-amz-security-token" not in headers

    def test_custom_service_and_region(self) -> None:
        auth = AwsSigV4Authenticator(_FULL_CREDENTIALS, region="eu-west-1", service="execute-api")
        signed = auth.authenticate(_request())

        auth_header = {k.lower(): v for k, v in signed.headers.items()}["authorization"]
        assert "execute-api" in auth_header
        assert "eu-west-1" in auth_header

    def test_host_is_signed(self) -> None:
        # botocore signs the host into SignedHeaders (the HTTP client materializes the
        # actual Host header at send time), so assert host is part of the signature.
        auth = AwsSigV4Authenticator(_FULL_CREDENTIALS)
        signed = auth.authenticate(_request())

        auth_header = {k.lower(): v for k, v in signed.headers.items()}["authorization"]
        signed_headers_clause = next(
            part for part in auth_header.split(", ") if part.startswith("SignedHeaders=")
        )
        assert "host" in signed_headers_clause

    def test_preserves_existing_headers(self) -> None:
        auth = AwsSigV4Authenticator(_FULL_CREDENTIALS)
        request = SignedRequest(
            url=_URL, method="POST", headers={"Content-Type": "application/json"}, body=b"{}"
        )
        signed = auth.authenticate(request)

        assert signed.headers["Content-Type"] == "application/json"

    def test_input_headers_are_included_in_signature(self) -> None:
        # A header passed in must appear in the signed SignedHeaders set, not just be
        # merged in unsigned afterwards.
        auth = AwsSigV4Authenticator(_FULL_CREDENTIALS)
        request = SignedRequest(
            url=_URL, method="POST", headers={"Content-Type": "application/json"}, body=b"{}"
        )
        signed = auth.authenticate(request)

        auth_header = {k.lower(): v for k, v in signed.headers.items()}["authorization"]
        signed_headers_clause = next(
            part for part in auth_header.split(", ") if part.startswith("SignedHeaders=")
        )
        assert "content-type" in signed_headers_clause

    def test_returns_new_request_without_mutating_input(self) -> None:
        auth = AwsSigV4Authenticator(_FULL_CREDENTIALS)
        request = _request()
        signed = auth.authenticate(request)

        assert "authorization" not in {k.lower() for k in request.headers}
        assert signed is not request


class TestCredentialValidation:
    def test_rejects_missing_access_key(self) -> None:
        creds = Credentials(access_key="", secret_key="secret")
        with pytest.raises(MissingCredentialsError, match="accessKeyId"):
            AwsSigV4Authenticator(creds)

    def test_rejects_missing_secret_key(self) -> None:
        creds = Credentials(access_key="AKIA", secret_key="")
        with pytest.raises(MissingCredentialsError, match="secretAccessKey"):
            AwsSigV4Authenticator(creds)

    def test_rejects_none_credentials(self) -> None:
        with pytest.raises(MissingCredentialsError, match="credentials"):
            AwsSigV4Authenticator(None)


class TestCreateEnvCredentialProvider:
    def test_success(self) -> None:
        env = {
            "AWS_ACCESS_KEY_ID": "AKID",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "AWS_SESSION_TOKEN": "tok",
        }
        with patch.dict(os.environ, env, clear=False):
            creds = create_env_credential_provider()
            assert creds.access_key == "AKID"
            assert creds.secret_key == "secret"
            assert creds.token == "tok"

    def test_missing_access_key(self) -> None:
        env = {"AWS_SECRET_ACCESS_KEY": "secret"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(MissingCredentialsError):
                create_env_credential_provider()

    def test_missing_secret_key(self) -> None:
        env = {"AWS_ACCESS_KEY_ID": "AKID"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(MissingCredentialsError):
                create_env_credential_provider()
