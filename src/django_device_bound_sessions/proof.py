"""Verification of DBSC proof JWTs (``typ: dbsc+jwt``)."""

import base64
import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from . import sf

#: A JSON Web Key (RFC 7517) as a decoded JSON object.
type JWK = dict[str, Any]
type PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey

SUPPORTED_ALGORITHMS = ("ES256", "RS256")
PROOF_TYP = "dbsc+jwt"
MIN_RSA_BITS = 2048

_PUBLIC_MEMBERS = {"EC": ("crv", "kty", "x", "y"), "RSA": ("e", "kty", "n")}
_PRIVATE_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}


class ProofError(Exception):
    """The proof is malformed or does not verify."""


@dataclass(frozen=True)
class Proof:
    """A verified proof JWT."""

    algorithm: str
    claims: dict[str, Any]


@dataclass(frozen=True)
class RegistrationProof(Proof):
    """A verified registration proof, with the public key it carried."""

    jwk: JWK


def parse_proof_header(value: str | None) -> str:
    """Extract the JWT from a ``Secure-Session-Response`` header.

    The spec makes it an sf-string; Chrome's docs show it bare, so a bare
    token is accepted too.
    """
    if not value:
        raise ProofError("Missing Secure-Session-Response header")
    try:
        token, _params = sf.parse_string_item(value)
    except sf.SFError as exc:
        raise ProofError(f"Malformed Secure-Session-Response header: {exc}") from exc
    return token


def public_jwk(jwk: JWK) -> JWK:
    """Reduce a JWK to its required public members (RFC 7638 order)."""
    kty = jwk.get("kty")
    if kty not in _PUBLIC_MEMBERS:
        raise ProofError(f"Unsupported key type: {kty!r}")
    try:
        return {k: jwk[k] for k in _PUBLIC_MEMBERS[kty]}
    except KeyError as exc:
        raise ProofError(f"JWK is missing member {exc}") from exc


def jwk_thumbprint(jwk: JWK) -> str:
    """RFC 7638 SHA-256 thumbprint, base64url without padding."""
    canonical = json.dumps(public_jwk(jwk), separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _load_key(jwk: object, algorithm: str) -> PublicKey:
    if not isinstance(jwk, dict):
        raise ProofError("JWK must be an object")
    jwk = cast(JWK, jwk)
    if _PRIVATE_MEMBERS & jwk.keys():
        raise ProofError("JWK contains private key material")
    expected_kty = "EC" if algorithm == "ES256" else "RSA"
    if jwk.get("kty") != expected_kty:
        raise ProofError(f"{algorithm} requires a {expected_kty} key")
    if algorithm == "ES256" and jwk.get("crv") != "P-256":
        raise ProofError("ES256 requires a P-256 key")
    try:
        key = jwt.PyJWK(public_jwk(jwk), algorithm=algorithm).key
    except (jwt.exceptions.PyJWKError, jwt.exceptions.InvalidKeyError, ValueError) as exc:
        raise ProofError(f"Invalid JWK: {exc}") from exc
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < MIN_RSA_BITS:
        raise ProofError(f"RSA keys must be at least {MIN_RSA_BITS} bits")
    if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        # Unreachable today: private JWKs were rejected above. Kept so a change
        # there can never let a non-public key through.
        raise ProofError("JWK is not a public key")  # pragma: no cover
    return key


def _unverified_header(token: str, allowed_algorithms: Iterable[str]) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.exceptions.DecodeError as exc:
        raise ProofError(f"Malformed JWT: {exc}") from exc
    if header.get("typ") != PROOF_TYP:
        raise ProofError(f"JWT typ must be {PROOF_TYP!r}")
    alg = header.get("alg")
    allowed = [a for a in allowed_algorithms if a in SUPPORTED_ALGORITHMS]
    if alg not in allowed:
        raise ProofError(f"Algorithm {alg!r} is not allowed")
    return header


def _decode(token: str, key: PublicKey, algorithm: str) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            options={
                "verify_aud": False,
                "verify_iss": False,
                # Chrome has been seen sending iat as a string; we don't rely
                # on it -- freshness comes from the signed challenge.
                "verify_iat": False,
                "require": ["jti"],
            },
        )
    except jwt.exceptions.InvalidTokenError as exc:
        raise ProofError(f"Proof verification failed: {exc}") from exc
    if not isinstance(claims.get("jti"), str):
        # PyJWT already rejects a non-string jti; don't rely on that alone.
        raise ProofError("jti must be a string")  # pragma: no cover
    return claims


def verify_registration_proof(
    token: str, allowed_algorithms: Iterable[str] = SUPPORTED_ALGORITHMS
) -> RegistrationProof:
    """Verify a registration proof, which carries its own public key."""
    header = _unverified_header(token, allowed_algorithms)
    alg = header["alg"]
    jwk = header.get("jwk")
    if jwk is None:
        raise ProofError("Registration proof must include a jwk header")
    key = _load_key(jwk, alg)
    claims = _decode(token, key, alg)
    return RegistrationProof(algorithm=alg, claims=claims, jwk=public_jwk(jwk))


def verify_refresh_proof(token: str, algorithm: str, jwk: JWK) -> Proof:
    """Verify a refresh proof against the key stored at registration."""
    _unverified_header(token, [algorithm])
    key = _load_key(jwk, algorithm)
    claims = _decode(token, key, algorithm)
    return Proof(algorithm=algorithm, claims=claims)
