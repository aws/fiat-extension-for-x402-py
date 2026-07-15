# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the DPoP key generation, JWK conversion, and thumbprint module."""

from __future__ import annotations

import base64
import hashlib
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from fiat_extension_x402.dpop import (
    DPoPKeyPair,
    compute_jwk_thumbprint,
    generate_dpop_keypair,
    to_dpop_jwk,
)
from fiat_extension_x402.exceptions import DPoPError
from fiat_extension_x402.schemas import DpopJwk


# ============================================================================
# Helpers
# ============================================================================


def _base64url_decode(s: str) -> bytes:
    """Decode base64url (no-pad) string."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _compute_thumbprint_independently(jwk_dict: dict[str, str]) -> str:
    """Compute RFC 7638 thumbprint independently for verification.

    Manually builds the canonical JSON (crv, kty, x, y — sorted), SHA-256, base64url.
    """
    canonical = json.dumps(
        {"crv": jwk_dict["crv"], "kty": jwk_dict["kty"], "x": jwk_dict["x"], "y": jwk_dict["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ============================================================================
# generate_dpop_keypair tests
# ============================================================================


class TestGenerateDpopKeypair:
    """Tests for generate_dpop_keypair."""

    def test_default_es256(self) -> None:
        """Default algorithm generates a P-256 key pair."""
        keypair = generate_dpop_keypair()

        assert isinstance(keypair, DPoPKeyPair)
        assert isinstance(keypair.private_key, EllipticCurvePrivateKey)
        assert isinstance(keypair.private_key.curve, SECP256R1)
        assert keypair.public_jwk["alg"] == "ES256"

    def test_es256_jwk_fields(self) -> None:
        """ES256 keypair public JWK has correct field set and values."""
        keypair = generate_dpop_keypair("ES256")

        jwk = keypair.public_jwk
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert jwk["alg"] == "ES256"
        assert jwk["use"] == "sig"
        assert "x" in jwk
        assert "y" in jwk
        # P-256 coordinates are 32 bytes => 43 base64url chars
        assert len(_base64url_decode(jwk["x"])) == 32
        assert len(_base64url_decode(jwk["y"])) == 32

    def test_es384(self) -> None:
        """ES384 generates a P-384 key pair."""
        keypair = generate_dpop_keypair("ES384")

        assert isinstance(keypair.private_key, EllipticCurvePrivateKey)
        assert isinstance(keypair.private_key.curve, SECP384R1)
        assert keypair.public_jwk["crv"] == "P-384"
        assert keypair.public_jwk["alg"] == "ES384"
        assert len(_base64url_decode(keypair.public_jwk["x"])) == 48
        assert len(_base64url_decode(keypair.public_jwk["y"])) == 48

    def test_es512(self) -> None:
        """ES512 generates a P-521 key pair."""
        keypair = generate_dpop_keypair("ES512")

        assert isinstance(keypair.private_key, EllipticCurvePrivateKey)
        assert isinstance(keypair.private_key.curve, SECP521R1)
        assert keypair.public_jwk["crv"] == "P-521"
        assert keypair.public_jwk["alg"] == "ES512"
        assert len(_base64url_decode(keypair.public_jwk["x"])) == 66
        assert len(_base64url_decode(keypair.public_jwk["y"])) == 66

    def test_rs256_generates_rsa_key(self) -> None:
        """RS256 generates a 2048-bit RSA key pair (not usable for Agent Pay DPoP)."""
        keypair = generate_dpop_keypair("RS256")

        assert isinstance(keypair.private_key, RSAPrivateKey)
        assert keypair.private_key.key_size == 2048
        jwk = keypair.public_jwk
        assert jwk["kty"] == "RSA"
        assert jwk["alg"] == "RS256"
        assert jwk["use"] == "sig"
        assert "n" in jwk
        assert "e" in jwk

    def test_unsupported_algorithm_raises(self) -> None:
        """Unsupported algorithm raises DPoPError."""
        with pytest.raises(DPoPError, match="Unsupported algorithm: ES999") as exc_info:
            generate_dpop_keypair("ES999")  # type: ignore[arg-type]

        assert exc_info.value.code == "DPOP_ERROR"
        assert exc_info.value.details == {"algorithm": "ES999"}

    def test_unique_keypairs(self) -> None:
        """Each call generates a distinct key pair."""
        kp1 = generate_dpop_keypair()
        kp2 = generate_dpop_keypair()

        assert kp1.public_jwk["x"] != kp2.public_jwk["x"]


# ============================================================================
# to_dpop_jwk tests
# ============================================================================


class TestToDpopJwk:
    """Tests for to_dpop_jwk."""

    def test_returns_dpop_jwk(self) -> None:
        """Converts keypair public key to validated DpopJwk."""
        keypair = generate_dpop_keypair("ES256")
        result = to_dpop_jwk(keypair)

        assert isinstance(result, DpopJwk)
        assert result.kty == "EC"
        assert result.crv == "P-256"
        assert result.x == keypair.public_jwk["x"]
        assert result.y == keypair.public_jwk["y"]

    def test_strips_extra_fields(self) -> None:
        """DpopJwk contains only kty, crv, x, y — no alg or use."""
        keypair = generate_dpop_keypair("ES256")
        result = to_dpop_jwk(keypair)

        dumped = result.model_dump()
        assert set(dumped.keys()) == {"kty", "crv", "x", "y"}

    def test_all_curves(self) -> None:
        """Works for all supported curves."""
        for alg, expected_crv in [("ES256", "P-256"), ("ES384", "P-384"), ("ES512", "P-521")]:
            keypair = generate_dpop_keypair(alg)  # type: ignore[arg-type]
            result = to_dpop_jwk(keypair)
            assert result.crv == expected_crv

    def test_rs256_key_raises(self) -> None:
        """An RS256 (RSA) key pair is rejected by to_dpop_jwk."""
        keypair = generate_dpop_keypair("RS256")
        with pytest.raises(DPoPError, match="Agent Pay only supports EC keys"):
            to_dpop_jwk(keypair)

    def test_non_ec_key_raises(self) -> None:
        """Non-EC key type raises DPoPError."""
        keypair = generate_dpop_keypair("ES256")
        # Manually corrupt the kty field
        keypair_bad = DPoPKeyPair(
            private_key=keypair.private_key,
            public_jwk={**keypair.public_jwk, "kty": "oct"},
        )
        with pytest.raises(DPoPError, match="Agent Pay only supports EC keys"):
            to_dpop_jwk(keypair_bad)

    def test_missing_crv_raises(self) -> None:
        """Missing crv field raises DPoPError."""
        keypair = generate_dpop_keypair("ES256")
        jwk_no_crv: dict[str, str] = {k: v for k, v in keypair.public_jwk.items() if k != "crv"}
        keypair_bad = DPoPKeyPair(
            private_key=keypair.private_key,
            public_jwk=jwk_no_crv,
        )
        with pytest.raises(DPoPError, match="missing crv, x, or y"):
            to_dpop_jwk(keypair_bad)


# ============================================================================
# compute_jwk_thumbprint tests
# ============================================================================


class TestComputeJwkThumbprint:
    """Tests for compute_jwk_thumbprint."""

    def test_thumbprint_matches_independent_computation(self) -> None:
        """Thumbprint matches an independent RFC 7638 implementation."""
        keypair = generate_dpop_keypair("ES256")
        dpop_jwk = to_dpop_jwk(keypair)

        result = compute_jwk_thumbprint(dpop_jwk)
        expected = _compute_thumbprint_independently(keypair.public_jwk)

        assert result == expected

    def test_thumbprint_is_base64url_no_pad(self) -> None:
        """Thumbprint is base64url without padding (SHA-256 = 32 bytes = 43 chars)."""
        keypair = generate_dpop_keypair("ES256")
        dpop_jwk = to_dpop_jwk(keypair)

        result = compute_jwk_thumbprint(dpop_jwk)

        # No padding chars
        assert "=" not in result
        # SHA-256 digest is 32 bytes -> ceil(32*4/3) = 43 base64url chars (no pad)
        assert len(result) == 43
        # Decodes back to 32 bytes
        decoded = _base64url_decode(result)
        assert len(decoded) == 32

    def test_thumbprint_deterministic(self) -> None:
        """Same key produces same thumbprint every time."""
        keypair = generate_dpop_keypair("ES256")
        dpop_jwk = to_dpop_jwk(keypair)

        t1 = compute_jwk_thumbprint(dpop_jwk)
        t2 = compute_jwk_thumbprint(dpop_jwk)

        assert t1 == t2

    def test_different_keys_different_thumbprints(self) -> None:
        """Different keys produce different thumbprints."""
        kp1 = generate_dpop_keypair("ES256")
        kp2 = generate_dpop_keypair("ES256")

        t1 = compute_jwk_thumbprint(to_dpop_jwk(kp1))
        t2 = compute_jwk_thumbprint(to_dpop_jwk(kp2))

        assert t1 != t2

    def test_known_answer_vector(self) -> None:
        """Verify the thumbprint against a precomputed known-answer value.

        The expected value is a fixed literal (computed offline from the canonical
        RFC 7638 JSON ``{"crv":"P-256","kty":"EC","x":...,"y":...}``), so this test
        is independent of the implementation's own JSON serialization.
        """
        # Fixed coordinates: 32 bytes of 0x01 (x) and 0x02 (y).
        x_b64 = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode("ascii")
        y_b64 = base64.urlsafe_b64encode(b"\x02" * 32).rstrip(b"=").decode("ascii")

        jwk = DpopJwk(kty="EC", crv="P-256", x=x_b64, y=y_b64)

        # Precomputed offline (not via the SDK) — true known-answer vector.
        expected_thumbprint = "kOFKxjJdOqJD5G4Yuw-cxHe64VGyxKEO_hoV83QfGj0"

        assert compute_jwk_thumbprint(jwk) == expected_thumbprint

    def test_all_curves_produce_valid_thumbprints(self) -> None:
        """Thumbprint works for all supported curves."""
        for alg in ("ES256", "ES384", "ES512"):
            keypair = generate_dpop_keypair(alg)
            dpop_jwk = to_dpop_jwk(keypair)
            result = compute_jwk_thumbprint(dpop_jwk)
            # All SHA-256 thumbprints are 43 base64url chars
            assert len(result) == 43
            assert "=" not in result


# ============================================================================
# DPoPError tests
# ============================================================================


class TestDPoPError:
    """Tests for the DPoPError exception class."""

    def test_inherits_agent_pay_error(self) -> None:
        """DPoPError is a subclass of AgentPayError."""
        from fiat_extension_x402.exceptions import AgentPayError

        err = DPoPError("test", {"key": "value"})
        assert isinstance(err, AgentPayError)
        assert err.code == "DPOP_ERROR"
        assert err.details == {"key": "value"}
        assert str(err) == "test"

    def test_details_optional(self) -> None:
        """DPoPError works without details."""
        err = DPoPError("no details")
        assert err.details is None


# ============================================================================
# Error path coverage (mocked failures)
# ============================================================================


class TestErrorPaths:
    """Tests that exercise error-handling branches via mocking."""

    def test_generate_keypair_key_generation_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """generate_dpop_keypair wraps unexpected key generation errors."""
        from fiat_extension_x402.dpop import key_generation

        def _boom(curve: object) -> None:
            raise RuntimeError("entropy source unavailable")

        monkeypatch.setattr(key_generation, "generate_private_key", _boom)

        with pytest.raises(DPoPError, match="Failed to generate DPoP key pair") as exc_info:
            generate_dpop_keypair("ES256")

        assert exc_info.value.details is not None
        assert "entropy source unavailable" in exc_info.value.details["error"]

    def test_compute_thumbprint_unexpected_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """compute_jwk_thumbprint wraps unexpected errors."""
        from unittest.mock import patch

        keypair = generate_dpop_keypair("ES256")
        dpop_jwk = to_dpop_jwk(keypair)

        with patch(
            "fiat_extension_x402.dpop.key_generation.json.dumps",
            side_effect=ValueError("serialization error"),
        ):
            with pytest.raises(DPoPError, match="Failed to compute JWK thumbprint"):
                compute_jwk_thumbprint(dpop_jwk)
