"""Public helpers for integrating DBSC into views and auth flows."""

import time
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Self, cast

from django.contrib.sessions.backends.base import SessionBase
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.urls import reverse

from .challenges import new_refresh_challenge, new_registration_challenge
from .conf import BINDING_KEY, OFFER_KEY, dbsc_settings
from .cookies import credential_attributes
from .proof import JWK
from .structured_fields import Token, serialize_inner_list, serialize_item

REGISTRATION_HEADER = "Secure-Session-Registration"
CHALLENGE_HEADER = "Secure-Session-Challenge"
RESPONSE_HEADER = "Secure-Session-Response"
SESSION_ID_HEADER = "Sec-Secure-Session-Id"


@dataclass(frozen=True)
class DeviceBinding:
    """The device key a Django session is bound to, stored in the session.

    Its lifetime is the Django session's: logging out or flushing the session
    removes it, which also ends the DBSC session in the browser.
    """

    session_id: str
    algorithm: str
    public_key: JWK
    thumbprint: str
    user_agent: str
    created_at: datetime
    last_refreshed_at: datetime | None = None

    def to_session(self) -> dict[str, Any]:
        # Plain JSON types so any SESSION_SERIALIZER/engine can store it.
        return {
            "id": self.session_id,
            "alg": self.algorithm,
            "jwk": self.public_key,
            "thumbprint": self.thumbprint,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat(),
            "last_refreshed_at": (
                self.last_refreshed_at.isoformat() if self.last_refreshed_at else None
            ),
        }

    @classmethod
    def from_session(cls, session: SessionBase) -> Self | None:
        stored: object = session.get(BINDING_KEY)
        if not isinstance(stored, dict):
            return None
        data = cast(dict[str, Any], stored)
        try:
            refreshed = data.get("last_refreshed_at")
            return cls(
                session_id=data["id"],
                algorithm=data["alg"],
                public_key=data["jwk"],
                thumbprint=data["thumbprint"],
                user_agent=data.get("user_agent", ""),
                created_at=datetime.fromisoformat(data["created_at"]),
                last_refreshed_at=datetime.fromisoformat(refreshed) if refreshed else None,
            )
        except (KeyError, TypeError, ValueError):
            return None

    def save(self, session: SessionBase) -> None:
        session[BINDING_KEY] = self.to_session()

    def refreshed(self, when: datetime) -> Self:
        return replace(self, last_refreshed_at=when)


@dataclass(frozen=True)
class DBSCState:
    """Attached to every request as ``request.dbsc``."""

    #: The device binding of this Django session, if it registered.
    binding: DeviceBinding | None = None
    #: True when the request carried a valid bound cookie for that binding.
    bound: bool = False

    @property
    def session_id(self) -> str | None:
        return self.binding.session_id if self.binding else None

    @property
    def registered(self) -> bool:
        return self.binding is not None


# There are three ways to reach the DBSC state from a view, depending on how
# the app types its requests:
#
# 1. Plain ``HttpRequest``: call ``get_dbsc_state(request)``.
# 2. ``DBSCHttpRequest``: use ``request.dbsc`` directly.
# 3. An app's own request class: add ``DBSCRequestMixin`` to it.


class DBSCRequestMixin:
    """Declares ``request.dbsc`` for an app's own typed request class::

        class AppRequest(DBSCRequestMixin, HttpRequest):
            tenant: Tenant

    For type checking only. The middleware sets the attribute at runtime.
    """

    dbsc: DBSCState


class DBSCHttpRequest(DBSCRequestMixin, HttpRequest):
    """``HttpRequest`` as seen behind :class:`DeviceBoundSessionMiddleware`.

    For type checking only; annotate views with it to use ``request.dbsc``::

        def view(request: DBSCHttpRequest) -> HttpResponse:
            if request.dbsc.bound: ...

    Views typed against a plain ``HttpRequest`` use :func:`get_dbsc_state`.
    """


def get_dbsc_state(request: HttpRequest) -> DBSCState:
    """The ``request.dbsc`` state, for code typed against a plain ``HttpRequest``.

    Raises ``ImproperlyConfigured`` if the middleware hasn't run on this
    request, so a missing middleware fails loudly instead of looking like an
    unbound session.
    """
    state = getattr(request, "dbsc", None)
    if not isinstance(state, DBSCState):
        raise ImproperlyConfigured(
            "request.dbsc is not set: add "
            "django_device_bound_sessions.middleware.DeviceBoundSessionMiddleware to MIDDLEWARE."
        )
    return state


def get_binding(request: HttpRequest) -> DeviceBinding | None:
    """The device binding for this request's session, or ``None``.

    Reads the session directly, so it works with or without the middleware.
    """
    return DeviceBinding.from_session(request.session)


def offer_registration(request: HttpRequest) -> None:
    """Ask the middleware to send ``Secure-Session-Registration`` on the
    next suitable (non-redirect) response for this session, within
    ``OFFER_MAX_AGE`` seconds.

    Called automatically on login when ``OFFER_ON_LOGIN`` is enabled. Has no
    effect on a session that is already bound: a binding is permanent for the
    life of the session, and binding a new device means logging in again.
    """
    request.session[OFFER_KEY] = int(time.time())


def registration_path() -> str:
    return dbsc_settings.REGISTRATION_PATH or reverse("django_device_bound_sessions:register")


def refresh_path() -> str:
    return dbsc_settings.REFRESH_PATH or reverse("django_device_bound_sessions:refresh")


def registration_header_value(request: HttpRequest) -> str:
    algorithms: list[str] = [Token(a) for a in dbsc_settings.ALGORITHMS if a != "none"]
    return serialize_inner_list(
        algorithms,
        {
            "path": registration_path(),
            "challenge": new_registration_challenge(request.session),
        },
    )


def challenge_header_value(session_id: str) -> str:
    """A ``Secure-Session-Challenge`` header value with a new refresh challenge."""
    return serialize_item(new_refresh_challenge(session_id), {"id": session_id})


def build_session_config(session_id: str) -> dict[str, Any]:
    """The JSON session instructions returned from registration/refresh."""
    s = dbsc_settings
    scope: dict[str, Any] = {"include_site": bool(s.SCOPE_INCLUDE_SITE)}
    if s.SCOPE_ORIGIN:
        scope["origin"] = s.SCOPE_ORIGIN
    if s.SCOPE_SPECIFICATION:
        scope["scope_specification"] = list(s.SCOPE_SPECIFICATION)
    config: dict[str, Any] = {
        "session_identifier": session_id,
        "refresh_url": refresh_path(),
        "scope": scope,
        "credentials": [
            {
                "type": "cookie",
                "name": s.BOUND_COOKIE_NAME,
                "attributes": credential_attributes(),
            }
        ],
    }
    if s.ALLOWED_REFRESH_INITIATORS:
        config["allowed_refresh_initiators"] = list(s.ALLOWED_REFRESH_INITIATORS)
    return config
