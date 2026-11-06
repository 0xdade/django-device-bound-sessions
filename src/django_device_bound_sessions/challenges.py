"""Stateless, signed, short-lived challenges with single-use enforcement.

A challenge is a value produced by ``django.core.signing`` that carries what
it is for. Its signature and timestamp prove we issued it recently; the cache
makes sure each one is only accepted once.
"""

import hashlib
import secrets
from typing import Any, cast

from django.contrib.sessions.backends.base import SessionBase
from django.core import signing
from django.core.cache import caches
from django.utils.crypto import constant_time_compare

from .conf import REGISTRATION_NONCE_KEY, dbsc_settings

REGISTRATION_SALT = "django_device_bound_sessions.challenge.registration"
REFRESH_SALT = "django_device_bound_sessions.challenge.refresh"


class ChallengeError(Exception):
    pass


class StaleChallenge(ChallengeError):
    """The challenge was ours, but has expired or was already used."""


def new_registration_challenge(session: SessionBase) -> str:
    """Issue a registration challenge tied to this Django session."""
    nonce = secrets.token_urlsafe(16)
    session[REGISTRATION_NONCE_KEY] = nonce
    return signing.dumps({"n": nonce}, salt=REGISTRATION_SALT)


def check_registration_challenge(session: SessionBase, challenge: str) -> None:
    data = _load(challenge, REGISTRATION_SALT)
    nonce = session.get(REGISTRATION_NONCE_KEY)
    if not nonce or not constant_time_compare(str(data.get("n", "")), nonce):
        raise ChallengeError("Registration challenge does not belong to this session")
    _consume(challenge)
    session.pop(REGISTRATION_NONCE_KEY, None)


def new_refresh_challenge(session_id: str) -> str:
    return signing.dumps({"s": session_id, "n": secrets.token_urlsafe(16)}, salt=REFRESH_SALT)


def check_refresh_challenge(session_id: str, challenge: str) -> None:
    data = _load(challenge, REFRESH_SALT)
    if not constant_time_compare(str(data.get("s", "")), session_id):
        raise ChallengeError("Challenge was issued for a different session")
    _consume(challenge)


def _load(challenge: str, salt: str) -> dict[str, Any]:
    try:
        data = signing.loads(challenge, salt=salt, max_age=dbsc_settings.CHALLENGE_MAX_AGE)
    except signing.SignatureExpired as exc:
        raise StaleChallenge("Challenge expired") from exc
    except signing.BadSignature as exc:
        raise ChallengeError("Invalid challenge") from exc
    if not isinstance(data, dict):
        raise ChallengeError("Invalid challenge")
    return cast(dict[str, Any], data)


def _consume(challenge: str) -> None:
    key = "django_device_bound_sessions:jti:" + hashlib.sha256(challenge.encode()).hexdigest()
    cache = caches[dbsc_settings.CACHE_ALIAS]
    # Keep the marker a little longer than the challenge can live.
    if not cache.add(key, 1, timeout=dbsc_settings.CHALLENGE_MAX_AGE + 60):
        raise StaleChallenge("Challenge already used")
