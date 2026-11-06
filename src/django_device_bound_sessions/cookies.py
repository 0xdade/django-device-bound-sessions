"""The short-lived cookie that DBSC binds to the device key."""

from django.core import signing
from django.http import HttpRequest, HttpResponseBase
from django.utils.crypto import constant_time_compare

from .conf import dbsc_settings

BOUND_COOKIE_SALT = "django_device_bound_sessions.bound_cookie"


def make_bound_value(session_id: str) -> str:
    return signing.dumps(session_id, salt=BOUND_COOKIE_SALT)


def verify_bound_cookie(request: HttpRequest, session_id: str) -> bool:
    value = request.COOKIES.get(dbsc_settings.BOUND_COOKIE_NAME)
    if not value:
        return False
    max_age = dbsc_settings.BOUND_COOKIE_AGE + dbsc_settings.BOUND_COOKIE_GRACE
    try:
        found = signing.loads(value, salt=BOUND_COOKIE_SALT, max_age=max_age)
    except signing.BadSignature:
        return False
    return isinstance(found, str) and constant_time_compare(found, session_id)


def set_bound_cookie(response: HttpResponseBase, session_id: str) -> None:
    s = dbsc_settings
    response.set_cookie(
        s.BOUND_COOKIE_NAME,
        make_bound_value(session_id),
        max_age=s.BOUND_COOKIE_AGE,
        domain=s.BOUND_COOKIE_DOMAIN,
        path=s.BOUND_COOKIE_PATH,
        secure=s.BOUND_COOKIE_SECURE,
        httponly=s.BOUND_COOKIE_HTTPONLY,
        samesite=s.BOUND_COOKIE_SAMESITE,
    )


def delete_bound_cookie(response: HttpResponseBase) -> None:
    s = dbsc_settings
    response.delete_cookie(
        s.BOUND_COOKIE_NAME,
        path=s.BOUND_COOKIE_PATH,
        domain=s.BOUND_COOKIE_DOMAIN,
        samesite=s.BOUND_COOKIE_SAMESITE,
    )


def credential_attributes() -> str:
    """Cookie attributes for the session config's ``credentials`` entry.

    These must match how the cookie is actually set, because the browser uses
    them to decide which cookie it is guarding.
    """
    s = dbsc_settings
    parts: list[str] = []
    if s.BOUND_COOKIE_DOMAIN:
        parts.append(f"Domain={s.BOUND_COOKIE_DOMAIN}")
    parts.append(f"Path={s.BOUND_COOKIE_PATH}")
    if s.BOUND_COOKIE_SECURE:
        parts.append("Secure")
    if s.BOUND_COOKIE_HTTPONLY:
        parts.append("HttpOnly")
    if s.BOUND_COOKIE_SAMESITE:
        parts.append(f"SameSite={s.BOUND_COOKIE_SAMESITE}")
    return "; ".join(parts)
