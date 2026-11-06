import time
from collections.abc import Callable
from typing import Any, cast

from django.contrib import auth
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponseBase

from .api import (
    REGISTRATION_HEADER,
    DBSCHttpRequest,
    DBSCState,
    DeviceBinding,
    registration_header_value,
)
from .conf import BINDING_KEY, OFFER_KEY, dbsc_settings
from .cookies import verify_bound_cookie


def _is_exempt(view_func: object) -> bool:
    return bool(getattr(view_func, "dbsc_exempt", False))


class DeviceBoundSessionMiddleware:
    """Enforces DBSC-bound sessions and offers registration.

    Place after ``SessionMiddleware`` and ``AuthenticationMiddleware``.

    - Sets ``request.dbsc`` (a :class:`~django_device_bound_sessions.api.DBSCState`).
    - If the Django session is bound to a device key but the request lacks
      a valid bound cookie, applies the ``ENFORCEMENT`` policy. This is what
      makes a stolen session cookie useless on another device.
    - Emits ``Secure-Session-Registration`` when an offer is pending.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponseBase]) -> None:
        self.get_response = get_response

    def __call__(self, http_request: HttpRequest) -> HttpResponseBase:
        request = cast(DBSCHttpRequest, http_request)
        if not hasattr(request, "session"):
            raise ImproperlyConfigured(
                "DeviceBoundSessionMiddleware requires SessionMiddleware to be installed before it."
            )
        binding = DeviceBinding.from_session(request.session)
        bound = binding is not None and verify_bound_cookie(request, binding.session_id)
        request.dbsc = DBSCState(binding=binding, bound=bound)

        response = self.get_response(request)
        self._maybe_offer(request, response)
        return response

    def process_view(
        self,
        http_request: HttpRequest,
        view_func: Callable[..., Any],
        view_args: tuple[Any, ...],
        view_kwargs: dict[str, Any],
    ) -> None:
        request = cast(DBSCHttpRequest, http_request)
        if _is_exempt(view_func):
            return None
        state = request.dbsc
        if state.registered and not state.bound:
            self._enforce(request)
        return None

    def _enforce(self, request: DBSCHttpRequest) -> None:
        mode = dbsc_settings.ENFORCEMENT
        if mode == "off":
            return
        if mode == "logout":
            # Flushing the session discards the binding along with it.
            auth.logout(request)
            request.dbsc = DBSCState()
            return
        if mode != "anonymous":
            raise ImproperlyConfigured(f"Unknown DBSC ENFORCEMENT mode: {mode!r}")
        anonymous = AnonymousUser()

        async def auser() -> AnonymousUser:
            return anonymous

        request.user = anonymous
        request.auser = auser

    def _maybe_offer(self, request: DBSCHttpRequest, response: HttpResponseBase) -> None:
        session = request.session
        offered_at = session.get(OFFER_KEY)
        match = request.resolver_match  # the view that handled this request
        if offered_at is None or (match is not None and _is_exempt(match.func)):
            return
        if (
            BINDING_KEY in session
            or auth.SESSION_KEY not in session
            or not isinstance(offered_at, int)
            or time.time() - offered_at > dbsc_settings.OFFER_MAX_AGE
        ):
            # Already bound, no longer logged in, or the offer went stale.
            session.pop(OFFER_KEY, None)
            return
        if 300 <= response.status_code < 400:
            # Wait for the page the redirect lands on.
            return
        response.headers[REGISTRATION_HEADER] = registration_header_value(request)
        session.pop(OFFER_KEY, None)
