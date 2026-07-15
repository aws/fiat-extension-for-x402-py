# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for DPoP proof creation."""

from __future__ import annotations

from unittest.mock import patch

import jwt as pyjwt
import pytest

from fiat_extension_x402.dpop import DPoPKeyPair, create_dpop_proof, generate_dpop_keypair


class TestCreateDpopProof:
    def test_creates_valid_jwt(self) -> None:
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(keypair, {"htm": "POST", "htu": "https://example.com/api"})
        header = pyjwt.get_unverified_header(proof)
        assert header["typ"] == "dpop+jwt"
        assert header["alg"] == "ES256"
        assert "jwk" in header

        claims = pyjwt.decode(proof, options={"verify_signature": False})
        assert claims["htm"] == "POST"
        assert claims["htu"] == "https://example.com/api"
        assert "jti" in claims
        assert "iat" in claims

    def test_includes_ath_when_access_token_provided(self) -> None:
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(
            keypair,
            {"htm": "GET", "htu": "https://example.com", "access_token": "mytoken"},
        )
        claims = pyjwt.decode(proof, options={"verify_signature": False})
        assert "ath" in claims

    def test_includes_nonce(self) -> None:
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(
            keypair,
            {"htm": "GET", "htu": "https://example.com", "nonce": "server-nonce"},
        )
        claims = pyjwt.decode(proof, options={"verify_signature": False})
        assert claims["nonce"] == "server-nonce"

    def test_normalizes_method_to_uppercase(self) -> None:
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(keypair, {"htm": "get", "htu": "https://example.com"})
        claims = pyjwt.decode(proof, options={"verify_signature": False})
        assert claims["htm"] == "GET"

    def test_unique_jti_per_proof(self) -> None:
        keypair = generate_dpop_keypair("ES256")
        proof1 = create_dpop_proof(keypair, {"htm": "GET", "htu": "https://example.com"})
        proof2 = create_dpop_proof(keypair, {"htm": "GET", "htu": "https://example.com"})
        jti1 = pyjwt.decode(proof1, options={"verify_signature": False})["jti"]
        jti2 = pyjwt.decode(proof2, options={"verify_signature": False})["jti"]
        assert jti1 != jti2

    def test_creates_verifiable_proof(self) -> None:
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(keypair, {"htm": "GET", "htu": "https://example.com"})
        header = pyjwt.get_unverified_header(proof)
        key = pyjwt.PyJWK.from_dict({**header["jwk"], "alg": "ES256"}).key
        claims = pyjwt.decode(proof, key, algorithms=["ES256"])
        assert claims["htm"] == "GET"

    def test_rs256_keys(self) -> None:
        keypair = generate_dpop_keypair("RS256")
        proof = create_dpop_proof(keypair, {"htm": "GET", "htu": "https://example.com"})
        header = pyjwt.get_unverified_header(proof)
        assert header["alg"] == "RS256"

    def test_missing_method_raises(self) -> None:
        from fiat_extension_x402.exceptions import DPoPError

        keypair = generate_dpop_keypair("ES256")
        with pytest.raises(DPoPError, match="HTTP method"):
            create_dpop_proof(keypair, {"htm": "", "htu": "https://example.com"})

    def test_missing_url_raises(self) -> None:
        from fiat_extension_x402.exceptions import DPoPError

        keypair = generate_dpop_keypair("ES256")
        with pytest.raises(DPoPError, match="HTTP URL"):
            create_dpop_proof(keypair, {"htm": "GET", "htu": ""})


class TestCreateDpopProofError:
    """Cover the exception path in create_dpop_proof."""

    def test_invalid_key_raises_dpop_error(self) -> None:
        from fiat_extension_x402.dpop.proof_creation import create_dpop_proof
        from fiat_extension_x402.exceptions import DPoPError

        # Construct a DPoPKeyPair with an invalid private key
        bad_keypair = DPoPKeyPair(
            private_key="not-a-key",  # type: ignore[arg-type]
            public_jwk={"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES256"},
        )
        with pytest.raises(DPoPError, match="Failed to create DPoP proof"):
            create_dpop_proof(bad_keypair, {"htm": "GET", "htu": "https://example.com"})

    def test_dpop_error_propagates_unwrapped(self) -> None:
        """A DPoPError raised internally propagates unchanged, not re-wrapped."""
        from fiat_extension_x402.dpop.proof_creation import create_dpop_proof
        from fiat_extension_x402.exceptions import DPoPError

        keypair = generate_dpop_keypair("ES256")
        sentinel = DPoPError("inner failure")
        with patch("fiat_extension_x402.dpop.proof_creation.pyjwt.encode", side_effect=sentinel):
            with pytest.raises(DPoPError) as exc_info:
                create_dpop_proof(keypair, {"htm": "GET", "htu": "https://example.com"})
        assert exc_info.value is sentinel
