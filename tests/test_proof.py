"""Proof JWT verification: every way a proof or its key can be rejected."""

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from django_device_bound_sessions.proof import (
    ProofError,
    jwk_thumbprint,
    parse_proof_header,
    public_jwk,
    verify_refresh_proof,
    verify_registration_proof,
)

EC_KEY = ec.generate_private_key(ec.SECP256R1())
EC_JWK = ECAlgorithm.to_jwk(EC_KEY.public_key(), as_dict=True)
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_JWK = RSAAlgorithm.to_jwk(RSA_KEY.public_key(), as_dict=True)


def sign(
    key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
    algorithm: str = "ES256",
    claims: dict[str, Any] | None = None,
    **headers: Any,
) -> str:
    return jwt.encode(
        {"jti": "challenge"} if claims is None else claims,
        key,
        algorithm=algorithm,
        headers={"typ": "dbsc+jwt", **headers},
    )


# --- Secure-Session-Response header ---------------------------------------


@pytest.mark.parametrize("value", [None, ""])
def test_header_missing(value):
    with pytest.raises(ProofError, match="Missing"):
        parse_proof_header(value)


@pytest.mark.parametrize("value", ['"unterminated', "(inner list)", "?1", "12"])
def test_header_not_a_string(value):
    with pytest.raises(ProofError, match="Malformed"):
        parse_proof_header(value)


def test_header_quoted_and_bare_jwt():
    token = sign(EC_KEY, jwk=EC_JWK)
    assert parse_proof_header(f'"{token}"') == token
    assert parse_proof_header(token) == token


# --- Registration proofs: the key they carry -------------------------------


@pytest.mark.parametrize(
    ("key", "alg", "key_jwk"),
    [(EC_KEY, "ES256", EC_JWK), (RSA_KEY, "RS256", RSA_JWK)],
    ids=["ES256", "RS256"],
)
def test_valid_registration_proofs(
    key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey, alg: str, key_jwk: dict[str, Any]
):
    proof = verify_registration_proof(sign(key, alg, jwk=key_jwk))
    assert proof.algorithm == alg
    assert proof.claims["jti"] == "challenge"
    assert proof.jwk == public_jwk(key_jwk)


def test_registration_requires_jwk():
    with pytest.raises(ProofError, match="must include a jwk"):
        verify_registration_proof(sign(EC_KEY))


def test_jwk_must_be_an_object():
    with pytest.raises(ProofError, match="must be an object"):
        verify_registration_proof(sign(EC_KEY, jwk="not-an-object"))


def test_jwk_with_private_key_material_is_rejected():
    private = ECAlgorithm.to_jwk(EC_KEY, as_dict=True)
    assert "d" in private
    with pytest.raises(ProofError, match="private key material"):
        verify_registration_proof(sign(EC_KEY, jwk=private))


def test_key_type_must_match_algorithm():
    with pytest.raises(ProofError, match="ES256 requires a EC key"):
        verify_registration_proof(sign(EC_KEY, "ES256", jwk=RSA_JWK))
    with pytest.raises(ProofError, match="RS256 requires a RSA key"):
        verify_registration_proof(sign(RSA_KEY, "RS256", jwk=EC_JWK))


def test_es256_requires_p256():
    p384 = ec.generate_private_key(ec.SECP384R1())
    p384_jwk = ECAlgorithm.to_jwk(p384.public_key(), as_dict=True)
    with pytest.raises(ProofError, match="P-256"):
        verify_registration_proof(sign(EC_KEY, jwk=p384_jwk))


def test_invalid_jwk_coordinates():
    bogus = {**EC_JWK, "x": "AAAA"}
    with pytest.raises(ProofError, match="Invalid JWK"):
        verify_registration_proof(sign(EC_KEY, jwk=bogus))


# Signing with a 1024-bit key is the point of this test; PyJWT warns about it.
@pytest.mark.filterwarnings("ignore:The RSA key is .* bits long")
def test_small_rsa_keys_are_rejected():
    # A deliberately weak key: this test proves we refuse it.
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    small_jwk = RSAAlgorithm.to_jwk(small.public_key(), as_dict=True)
    with pytest.raises(ProofError, match="at least 2048 bits"):
        verify_registration_proof(sign(small, "RS256", jwk=small_jwk))


def test_jwk_missing_members():
    with pytest.raises(ProofError, match="missing member"):
        verify_registration_proof(sign(EC_KEY, jwk={"kty": "EC", "crv": "P-256", "x": "A"}))


def test_unsupported_key_type():
    with pytest.raises(ProofError, match="Unsupported key type"):
        public_jwk({"kty": "oct", "k": "secret"})


def test_algorithm_must_be_allowed():
    token = sign(RSA_KEY, "RS256", jwk=RSA_JWK)
    with pytest.raises(ProofError, match="not allowed"):
        verify_registration_proof(token, allowed_algorithms=["ES256"])


def test_hs256_is_never_allowed():
    """A symmetric algorithm must be refused even if someone lists it."""
    token = jwt.encode(
        {"jti": "challenge"},
        "a-shared-secret-that-is-long-enough-for-hs256",
        algorithm="HS256",
        headers={"typ": "dbsc+jwt", "jwk": EC_JWK},
    )
    with pytest.raises(ProofError, match="not allowed"):
        verify_registration_proof(token, allowed_algorithms=["HS256", "ES256"])


# --- Token-level checks ----------------------------------------------------


def test_malformed_jwt():
    with pytest.raises(ProofError, match="Malformed JWT"):
        verify_registration_proof("not.a.jwt")


def test_jti_is_required():
    with pytest.raises(ProofError, match="verification failed"):
        verify_registration_proof(sign(EC_KEY, claims={"other": 1}, jwk=EC_JWK))


def test_jti_must_be_a_string():
    with pytest.raises(ProofError):
        verify_registration_proof(sign(EC_KEY, claims={"jti": 123}, jwk=EC_JWK))


def test_expired_proof_is_rejected():
    claims = {"jti": "challenge", "exp": int(time.time()) - 60}
    with pytest.raises(ProofError, match="verification failed"):
        verify_registration_proof(sign(EC_KEY, claims=claims, jwk=EC_JWK))


def test_string_iat_is_accepted():
    """Chrome has been seen sending iat as a string; it must not break us."""
    claims = {"jti": "challenge", "iat": "1725579055"}
    assert verify_registration_proof(sign(EC_KEY, claims=claims, jwk=EC_JWK)).claims == claims


# --- Refresh proofs: verified against the stored key ------------------------


def test_refresh_proof_round_trip():
    proof = verify_refresh_proof(sign(EC_KEY), "ES256", public_jwk(EC_JWK))
    assert proof.claims["jti"] == "challenge"


def test_refresh_proof_algorithm_must_match_stored_key():
    with pytest.raises(ProofError, match="not allowed"):
        verify_refresh_proof(sign(RSA_KEY, "RS256"), "ES256", public_jwk(EC_JWK))


def test_refresh_proof_signed_by_another_key():
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ProofError, match="verification failed"):
        verify_refresh_proof(sign(other), "ES256", public_jwk(EC_JWK))


def test_refresh_ignores_a_jwk_header():
    """The stored key is authoritative; a jwk in the header can't override it."""
    other = ec.generate_private_key(ec.SECP256R1())
    other_jwk = ECAlgorithm.to_jwk(other.public_key(), as_dict=True)
    with pytest.raises(ProofError, match="verification failed"):
        verify_refresh_proof(sign(other, jwk=other_jwk), "ES256", public_jwk(EC_JWK))


# --- Thumbprints -------------------------------------------------------------


def test_rfc7638_thumbprint():
    # The example key and thumbprint from RFC 7638, section 3.1.
    rfc_key = {
        "kty": "RSA",
        "n": (
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc"
            "_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR"
            "0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTW"
            "hAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        ),
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29",
    }
    assert jwk_thumbprint(rfc_key) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
