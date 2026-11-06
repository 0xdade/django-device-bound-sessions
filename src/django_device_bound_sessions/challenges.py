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
    """Issue a registration challenge tied to this Django session.

    It's answered right away and only exists before the session is bound, so
    it gets the short ``CHALLENGE_MAX_AGE``.
    """
    nonce = secrets.token_urlsafe(16)
    session[REGISTRATION_NONCE_KEY] = nonce
    return signing.dumps({"n": nonce}, salt=REGISTRATION_SALT)


def check_registration_challenge(session: SessionBase, challenge: str) -> None:
    max_age = dbsc_settings.CHALLENGE_MAX_AGE
    data = _load(challenge, REGISTRATION_SALT, max_age)
    nonce = session.get(REGISTRATION_NONCE_KEY)
    if not nonce or not constant_time_compare(str(data.get("n", "")), nonce):
        raise ChallengeError("Registration challenge does not belong to this session")
    _consume(challenge, max_age)
    session.pop(REGISTRATION_NONCE_KEY, None)


def refresh_challenge_lifetime() -> int:
    """Seconds a refresh challenge stays valid: as long as a bound cookie.

    The browser caches the challenge sent with each new bound cookie and signs
    it when that cookie expires, so a challenge must last as long as the server
    accepts the cookie: ``BOUND_COOKIE_AGE + BOUND_COOKIE_GRACE``. Challenges
    sent with a 403 get the same lifetime; a shorter one wouldn't narrow the
    worst case, which these two settings define.
    """
    return dbsc_settings.BOUND_COOKIE_AGE + dbsc_settings.BOUND_COOKIE_GRACE


def new_refresh_challenge(session_id: str) -> str:
    return signing.dumps({"s": session_id, "n": secrets.token_urlsafe(16)}, salt=REFRESH_SALT)


def check_refresh_challenge(session_id: str, challenge: str) -> None:
    max_age = refresh_challenge_lifetime()
    data = _load(challenge, REFRESH_SALT, max_age)
    if not constant_time_compare(str(data.get("s", "")), session_id):
        raise ChallengeError("Challenge was issued for a different session")
    _consume(challenge, max_age)


def _load(challenge: str, salt: str, max_age: int) -> dict[str, Any]:
    try:
        data = signing.loads(challenge, salt=salt, max_age=max_age)
    except signing.SignatureExpired as exc:
        raise StaleChallenge("Challenge expired") from exc
    except signing.BadSignature as exc:
        raise ChallengeError("Invalid challenge") from exc
    if not isinstance(data, dict):
        raise ChallengeError("Invalid challenge")
    return cast(dict[str, Any], data)


def _consume(challenge: str, max_age: int) -> None:
    key = "django_device_bound_sessions:jti:" + hashlib.sha256(challenge.encode()).hexdigest()
    cache = caches[dbsc_settings.CACHE_ALIAS]
    # Remember it a little longer than this challenge can live, so it can't be
    # replayed after the cache forgets it.
    if not cache.add(key, 1, timeout=max_age + 60):
        raise StaleChallenge("Challenge already used")
