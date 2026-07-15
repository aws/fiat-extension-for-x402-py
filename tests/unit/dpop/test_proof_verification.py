# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for DPoP proof verification."""

from __future__ import annotations

import time
from typing import Any

import jwt as pyjwt
import pytest

from fiat_extension_x402.dpop import (
    DPoPKeyPair,
    create_dpop_proof,
    extract_dpop_thumbprint,
    generate_dpop_keypair,
    verify_dpop_proof,
)


class TestVerifyDpopProof:
    def _make_proof(self, keypair: DPoPKeyPair, **kwargs: Any) -> str:
        opts: dict[str, Any] = {"htm": "POST", "htu": "https://example.com"}
        opts.update(kwargs)
        return create_dpop_proof(keypair, opts)

    def test_valid_proof(self) -> None:
        keypair = generate_dpop_keypair("ES256")
        proof = self._make_proof(keypair)
        claims = verify_dpop_proof(proof, {"htm": "POST", "htu": "https://example.com"})
        assert claims["htm"] == "POST"

    def test_wrong_htm(self) -> None:
        keypair = generate_dpop_keypair("ES256")
        proof = self._make_proof(keypair)
        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError, match="htm mismatch"):
            verify_dpop_proof(proof, {"htm": "GET", "htu": "https://example.com"})

    def test_expired_proof(self) -> None:
        keypair = generate_dpop_keypair("ES256")
        # Create a proof with a backdated iat so it's definitely expired
        import jwt as _pyjwt

        payload = {
            "jti": "test-jti",
            "htm": "POST",
            "htu": "https://example.com",
            "iat": int(time.time()) - 200,  # 200s ago
        }
        headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": keypair.public_jwk}
        proof = _pyjwt.encode(payload, keypair.private_key, algorithm="ES256", headers=headers)

        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError, match="expired"):
            verify_dpop_proof(
                proof,
                {"htm": "POST", "htu": "https://example.com", "max_age": 60},
            )


class TestVerifyDpopProofAdditional:
    """Cover additional paths in verify_dpop_proof."""

    def test_invalid_typ(self) -> None:
        """DPoP proof with wrong typ is rejected."""
        keypair = generate_dpop_keypair("ES256")
        payload = {
            "jti": "id",
            "htm": "POST",
            "htu": "https://example.com",
            "iat": int(time.time()),
        }
        # Use wrong typ
        headers = {"typ": "JWT", "alg": "ES256", "jwk": keypair.public_jwk}
        proof = pyjwt.encode(payload, keypair.private_key, algorithm="ES256", headers=headers)

        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError, match="type"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": "https://example.com"})

    def test_undecodable_header(self) -> None:
        """A proof whose header cannot be decoded is rejected."""
        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError, match="cannot decode header"):
            verify_dpop_proof("not-a-jwt", {"htm": "POST", "htu": "https://example.com"})

    def test_missing_jwk(self) -> None:
        """DPoP proof without jwk in header is rejected."""
        keypair = generate_dpop_keypair("ES256")
        payload = {
            "jti": "id",
            "htm": "POST",
            "htu": "https://example.com",
            "iat": int(time.time()),
        }
        headers = {"typ": "dpop+jwt", "alg": "ES256"}
        proof = pyjwt.encode(payload, keypair.private_key, algorithm="ES256", headers=headers)

        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError, match="jwk"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": "https://example.com"})

    def test_future_iat(self) -> None:
        """DPoP proof with iat far in the future is rejected."""
        keypair = generate_dpop_keypair("ES256")
        payload = {
            "jti": "id",
            "htm": "POST",
            "htu": "https://example.com",
            "iat": int(time.time()) + 100,  # 100 seconds in the future
        }
        headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": keypair.public_jwk}
        # Disable iat verification at PyJWT level so our code's check is exercised
        proof = pyjwt.encode(payload, keypair.private_key, algorithm="ES256", headers=headers)

        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError):
            verify_dpop_proof(proof, {"htm": "POST", "htu": "https://example.com"})

    def test_missing_required_claim(self) -> None:
        """A signed proof missing a required claim (htu) is rejected."""
        keypair = generate_dpop_keypair("ES256")
        payload = {
            "jti": "id",
            "htm": "POST",
            # htu intentionally omitted
            "iat": int(time.time()),
        }
        headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": keypair.public_jwk}
        proof = pyjwt.encode(payload, keypair.private_key, algorithm="ES256", headers=headers)

        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError, match="Missing required DPoP claims"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": "https://example.com"})

    def test_htu_mismatch(self) -> None:
        """DPoP proof with wrong htu is rejected."""
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(keypair, {"htm": "POST", "htu": "https://example.com"})

        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError, match="htu mismatch"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": "https://other.com"})

    def test_ath_mismatch(self) -> None:
        """DPoP proof with wrong access token hash is rejected."""
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(
            keypair,
            {"htm": "POST", "htu": "https://example.com", "access_token": "token-a"},
        )

        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError, match="ath"):
            verify_dpop_proof(
                proof,
                {"htm": "POST", "htu": "https://example.com", "access_token": "token-b"},
            )

    def test_bad_signature(self) -> None:
        """DPoP proof with invalid signature fails."""
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(keypair, {"htm": "POST", "htu": "https://example.com"})
        # Tamper with signature (last few chars)
        tampered = proof[:-4] + "XXXX"

        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError, match="signature"):
            verify_dpop_proof(tampered, {"htm": "POST", "htu": "https://example.com"})


class TestVerifyDpopProofMissingAlg:
    """Cover missing alg header in DPoP proof (line 63 of proof_verification.py)."""

    def test_missing_alg(self) -> None:
        """A forged token without alg triggers DPoPError."""
        from fiat_extension_x402.exceptions import DPoPError

        # Manually construct a JWT with typ=dpop+jwt, jwk present, but no alg
        # We can't easily do this with pyjwt (it requires alg), so we mock the header
        import base64
        import json

        header = {"typ": "dpop+jwt", "jwk": {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}}
        payload_obj = {"jti": "x", "htm": "POST", "htu": "https://x.com", "iat": int(time.time())}
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload_obj).encode()).rstrip(b"=").decode()
        fake_proof = f"{h}.{p}.fakesig"

        with pytest.raises(DPoPError):
            verify_dpop_proof(fake_proof, {"htm": "POST", "htu": "https://x.com"})


class _InMemoryNonceStore:
    """In-memory replay store keyed on the proof id (jti)."""

    def __init__(self) -> None:
        self.seen: set[str] = set()

    def has(self, jti: str) -> bool:
        return jti in self.seen

    def add(self, jti: str, expires_at: int) -> None:
        self.seen.add(jti)


class TestVerifyDpopProofNonceStore:
    """Cover the nonce_store replay-prevention path."""

    def test_detects_replay(self) -> None:
        """Verifying the same proof twice with a nonce store is rejected."""
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(keypair, {"htm": "POST", "htu": "https://example.com"})
        store = _InMemoryNonceStore()

        # First verification succeeds and records the jti.
        verify_dpop_proof(
            proof,
            {"htm": "POST", "htu": "https://example.com", "nonce_store": store},
        )

        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError, match="replay detected"):
            verify_dpop_proof(
                proof,
                {"htm": "POST", "htu": "https://example.com", "nonce_store": store},
            )

    def test_allows_distinct_proofs(self) -> None:
        """Distinct proofs (different jti) both verify against one nonce store."""
        keypair = generate_dpop_keypair("ES256")
        store = _InMemoryNonceStore()
        proof1 = create_dpop_proof(keypair, {"htm": "POST", "htu": "https://example.com"})
        proof2 = create_dpop_proof(keypair, {"htm": "POST", "htu": "https://example.com"})

        verify_dpop_proof(
            proof1,
            {"htm": "POST", "htu": "https://example.com", "nonce_store": store},
        )
        verify_dpop_proof(
            proof2,
            {"htm": "POST", "htu": "https://example.com", "nonce_store": store},
        )


class TestExtractDpopThumbprint:
    def test_extracts_thumbprint(self) -> None:
        keypair = generate_dpop_keypair("ES256")
        proof = create_dpop_proof(keypair, {"htm": "GET", "htu": "https://example.com"})
        thumbprint = extract_dpop_thumbprint(proof)
        assert isinstance(thumbprint, str)
        assert len(thumbprint) > 20

    def test_invalid_proof(self) -> None:
        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError):
            extract_dpop_thumbprint("not-a-jwt")


class TestExtractDpopThumbprintAdditional:
    """Cover RSA key type path in extract_dpop_thumbprint."""

    def test_rsa_key(self) -> None:
        keypair = generate_dpop_keypair("RS256")
        proof = create_dpop_proof(keypair, {"htm": "GET", "htu": "https://example.com"})
        thumbprint = extract_dpop_thumbprint(proof)
        assert isinstance(thumbprint, str)
        assert len(thumbprint) > 20

    def test_unsupported_key_type(self) -> None:
        """A proof with unsupported key type raises DPoPError."""
        keypair = generate_dpop_keypair("ES256")
        payload = {
            "jti": "id",
            "htm": "GET",
            "htu": "https://example.com",
            "iat": int(time.time()),
        }
        # Forge a jwk with unsupported kty
        bad_jwk = {**keypair.public_jwk, "kty": "OKP"}
        headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": bad_jwk}
        proof = pyjwt.encode(payload, keypair.private_key, algorithm="ES256", headers=headers)

        from fiat_extension_x402.exceptions import DPoPError

        with pytest.raises(DPoPError, match="Unsupported key type"):
            extract_dpop_thumbprint(proof)


class TestExtractDpopThumbprintMissingJwk:
    """Cover missing jwk path in extract_dpop_thumbprint (line 138)."""

    def test_missing_jwk_raises(self) -> None:
        from fiat_extension_x402.exceptions import DPoPError

        keypair = generate_dpop_keypair("ES256")
        payload = {"jti": "x", "htm": "GET", "htu": "https://x.com", "iat": int(time.time())}
        # No jwk in header
        headers = {"typ": "dpop+jwt", "alg": "ES256"}
        proof = pyjwt.encode(payload, keypair.private_key, algorithm="ES256", headers=headers)

        with pytest.raises(DPoPError, match="jwk"):
            extract_dpop_thumbprint(proof)
