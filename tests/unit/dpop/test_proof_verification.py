# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for DPoP proof verification."""

from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from fiat_extension_x402.dpop import (
    compute_jwk_thumbprint,
    extract_dpop_thumbprint,
    verify_dpop_proof,
)
from fiat_extension_x402.exceptions import DPoPError
from tests.support import dpop_proof, ec_key

HTU = "https://example.com/resource"


def _public(jwk: dict[str, str]) -> dict[str, str]:
    return {k: jwk[k] for k in ("kty", "crv", "x", "y")}


def _claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "jti": str(uuid.uuid4()),
        "htm": "POST",
        "htu": HTU,
        "iat": int(time.time()),
    }
    claims.update(overrides)
    return claims


def _signed(
    claims: dict[str, Any],
    private_key: Any,
    headers: dict[str, Any],
    algorithm: str = "ES256",
) -> str:
    token: str = pyjwt.encode(claims, private_key, algorithm=algorithm, headers=headers)
    return token


def _b64(value: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


class _InMemoryNonceStore:
    """In-memory replay store keyed on the proof id (jti)."""

    def __init__(self) -> None:
        self.seen: dict[str, int] = {}

    def has(self, jti: str) -> bool:
        return jti in self.seen

    def add(self, jti: str, expires_at: int) -> None:
        self.seen[jti] = expires_at


class TestVerifyDpopProof:
    def test_valid_proof(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="POST", htu=HTU)
        claims = verify_dpop_proof(proof, {"htm": "POST", "htu": HTU})
        assert claims["htm"] == "POST"
        assert claims["htu"] == HTU

    def test_valid_proof_with_access_token(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="GET", htu=HTU, access_token="token-a")
        claims = verify_dpop_proof(proof, {"htm": "GET", "htu": HTU, "access_token": "token-a"})
        assert "ath" in claims

    def test_no_expected_htm_or_htu_skips_binding_checks(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="DELETE", htu="https://elsewhere.test")
        assert verify_dpop_proof(proof, {})["htm"] == "DELETE"

    def test_rsa_proof(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
        proof = _signed(_claims(), private_key, {"typ": "dpop+jwt", "jwk": public_jwk}, "RS256")
        assert verify_dpop_proof(proof, {"htm": "POST", "htu": HTU})["htu"] == HTU

    def test_wrong_htm(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="POST", htu=HTU)
        with pytest.raises(DPoPError, match="htm mismatch"):
            verify_dpop_proof(proof, {"htm": "GET", "htu": HTU})

    def test_htu_mismatch(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="POST", htu=HTU)
        with pytest.raises(DPoPError, match="htu mismatch"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": "https://other.com"})

    def test_expired_proof(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="POST", htu=HTU, iat=int(time.time()) - 200)
        with pytest.raises(DPoPError, match="expired"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU, "max_age": 60})

    def test_default_max_age_applies(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="POST", htu=HTU, iat=int(time.time()) - 120)
        with pytest.raises(DPoPError, match="expired"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU})

    def test_future_iat(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="POST", htu=HTU, iat=int(time.time()) + 100)
        with pytest.raises(DPoPError, match="future"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU})

    def test_iat_within_clock_skew_is_accepted(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="POST", htu=HTU, iat=int(time.time()) + 2)
        assert verify_dpop_proof(proof, {"htm": "POST", "htu": HTU})

    def test_ath_mismatch(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="POST", htu=HTU, access_token="token-a")
        with pytest.raises(DPoPError, match="ath"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU, "access_token": "token-b"})

    def test_missing_ath_when_access_token_expected(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="POST", htu=HTU)
        with pytest.raises(DPoPError, match="ath"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU, "access_token": "token-a"})

    def test_bad_signature(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="POST", htu=HTU)
        tampered = proof[:-4] + ("AAAA" if not proof.endswith("AAAA") else "BBBB")
        with pytest.raises(DPoPError, match="signature"):
            verify_dpop_proof(tampered, {"htm": "POST", "htu": HTU})

    def test_signed_by_key_other_than_header_jwk(self) -> None:
        key, _ = ec_key("buyer")
        _, other_jwk = ec_key("other")
        proof = _signed(_claims(), key, {"typ": "dpop+jwt", "jwk": _public(other_jwk)})
        with pytest.raises(DPoPError, match="signature"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU})


class TestVerifyDpopProofHeader:
    def test_undecodable_header(self) -> None:
        with pytest.raises(DPoPError, match="cannot decode header"):
            verify_dpop_proof("not-a-jwt", {"htm": "POST", "htu": HTU})

    def test_invalid_typ(self) -> None:
        key, jwk = ec_key("buyer")
        proof = _signed(_claims(), key, {"typ": "JWT", "jwk": _public(jwk)})
        with pytest.raises(DPoPError, match="type"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU})

    def test_typ_is_case_insensitive(self) -> None:
        key, jwk = ec_key("buyer")
        proof = _signed(_claims(), key, {"typ": "DPoP+JWT", "jwk": _public(jwk)})
        assert verify_dpop_proof(proof, {"htm": "POST", "htu": HTU})

    def test_missing_jwk(self) -> None:
        key, _ = ec_key("buyer")
        proof = _signed(_claims(), key, {"typ": "dpop+jwt"})
        with pytest.raises(DPoPError, match="jwk"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU})

    def test_missing_alg(self) -> None:
        _, jwk = ec_key("buyer")
        header = {"typ": "dpop+jwt", "jwk": _public(jwk)}
        fake_proof = f"{_b64(header)}.{_b64(_claims())}.fakesig"
        with pytest.raises(DPoPError, match="missing 'alg'"):
            verify_dpop_proof(fake_proof, {"htm": "POST", "htu": HTU})

    def test_hs256_proof_is_rejected(self) -> None:
        _, jwk = ec_key("buyer")
        proof = _signed(
            _claims(),
            "a-shared-secret-that-is-at-least-32-bytes",
            {"typ": "dpop+jwt", "jwk": _public(jwk)},
            "HS256",
        )
        with pytest.raises(DPoPError, match="algorithm not allowed: HS256"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU})

    def test_none_alg_proof_is_rejected(self) -> None:
        _, jwk = ec_key("buyer")
        header = {"typ": "dpop+jwt", "alg": "none", "jwk": _public(jwk)}
        fake_proof = f"{_b64(header)}.{_b64(_claims())}."
        with pytest.raises(DPoPError, match="algorithm not allowed: none"):
            verify_dpop_proof(fake_proof, {"htm": "POST", "htu": HTU})

    def test_missing_required_claim(self) -> None:
        key, jwk = ec_key("buyer")
        claims = _claims()
        del claims["htu"]
        proof = _signed(claims, key, {"typ": "dpop+jwt", "jwk": _public(jwk)})
        with pytest.raises(DPoPError, match="Missing required DPoP claims"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU})


class TestVerifyDpopProofNonceStore:
    def test_detects_replay(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="POST", htu=HTU)
        store = _InMemoryNonceStore()

        claims = verify_dpop_proof(proof, {"htm": "POST", "htu": HTU, "nonce_store": store})
        assert store.seen[claims["jti"]] == claims["iat"] + 60

        with pytest.raises(DPoPError, match="replay detected"):
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU, "nonce_store": store})

    def test_allows_distinct_proofs(self) -> None:
        key, jwk = ec_key("buyer")
        store = _InMemoryNonceStore()
        for _ in range(2):
            proof = dpop_proof(key, jwk, htm="POST", htu=HTU)
            verify_dpop_proof(proof, {"htm": "POST", "htu": HTU, "nonce_store": store})
        assert len(store.seen) == 2


class TestExtractDpopThumbprint:
    def test_matches_compute_jwk_thumbprint(self) -> None:
        key, jwk = ec_key("buyer")
        proof = dpop_proof(key, jwk, htm="GET", htu=HTU)
        assert extract_dpop_thumbprint(proof) == compute_jwk_thumbprint(jwk)

    def test_invalid_proof(self) -> None:
        with pytest.raises(DPoPError, match="Cannot extract thumbprint"):
            extract_dpop_thumbprint("not-a-jwt")

    def test_missing_jwk_raises(self) -> None:
        key, _ = ec_key("buyer")
        proof = _signed(_claims(), key, {"typ": "dpop+jwt"})
        with pytest.raises(DPoPError, match="jwk"):
            extract_dpop_thumbprint(proof)

    def test_unsupported_key_type(self) -> None:
        key, jwk = ec_key("buyer")
        proof = _signed(_claims(), key, {"typ": "dpop+jwt", "jwk": {**_public(jwk), "kty": "OKP"}})
        with pytest.raises(DPoPError, match="Unsupported key type"):
            extract_dpop_thumbprint(proof)


class TestComputeJwkThumbprint:
    def test_rfc7638_example(self) -> None:
        # RFC 7638 section 3.1 example key and its thumbprint.
        jwk = {
            "kty": "RSA",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6"
                "tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5"
                "v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS"
                "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-k"
                "EgU8awapJzKnqDKgw"
            ),
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29",
        }
        assert compute_jwk_thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

    def test_ignores_non_required_members(self) -> None:
        _, jwk = ec_key("buyer")
        assert compute_jwk_thumbprint(jwk) == compute_jwk_thumbprint(_public(jwk))

    def test_distinct_keys_have_distinct_thumbprints(self) -> None:
        _, jwk_a = ec_key("a", ec.SECP256R1())
        _, jwk_b = ec_key("b", ec.SECP256R1())
        assert compute_jwk_thumbprint(jwk_a) != compute_jwk_thumbprint(jwk_b)

    def test_missing_kty(self) -> None:
        with pytest.raises(DPoPError, match="Unsupported key type"):
            compute_jwk_thumbprint({})
