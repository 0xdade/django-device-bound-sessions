"""Downstream typing contract. Checked by ``uv run mypy``, never executed.

Written the way an app would use django-device-bound-sessions, in mypy strict mode. Each
``assert_type`` pins down an exact type. Each ``# type: ignore[code]`` marks a
mistake that MUST be rejected: with ``warn_unused_ignores`` (on in strict
mode), mypy fails if that error ever stops being reported.
"""

from datetime import datetime
from typing import assert_type

from django.http import HttpRequest, HttpResponse
from django.urls import URLPattern, path

from django_device_bound_sessions.api import (
    DBSCHttpRequest,
    DBSCRequestMixin,
    DBSCState,
    DeviceBinding,
    get_binding,
    get_dbsc_state,
)
from django_device_bound_sessions.conf import DBSCConfig
from django_device_bound_sessions.decorators import dbsc_exempt

# --- 1. Views typed against plain HttpRequest (no type changes needed) ------


def plain_view(request: HttpRequest) -> HttpResponse:
    state = get_dbsc_state(request)
    assert_type(state, DBSCState)
    assert_type(state.bound, bool)
    assert_type(state.registered, bool)
    assert_type(state.session_id, str | None)
    assert_type(state.binding, DeviceBinding | None)
    assert_type(get_binding(request), DeviceBinding | None)

    if state.binding is not None:
        assert_type(state.binding.algorithm, str)
        assert_type(state.binding.created_at, datetime)
        assert_type(state.binding.last_refreshed_at, datetime | None)

    # A plain HttpRequest doesn't claim to have .dbsc.
    request.dbsc  # type: ignore[attr-defined]
    return HttpResponse()


def unnarrowed(request: HttpRequest) -> str:
    # The binding is optional and must be narrowed before use.
    return get_dbsc_state(request).binding.algorithm  # type: ignore[union-attr]


# --- 2. Views typed with DBSCHttpRequest --------------------------------------


def dbsc_view(request: DBSCHttpRequest) -> HttpResponse:
    assert_type(request.dbsc, DBSCState)
    # Still an HttpRequest: helpers typed for HttpRequest accept it.
    assert_type(get_dbsc_state(request), DBSCState)
    # Middleware internals are not part of the public type.
    request._dbsc_exempt  # type: ignore[attr-defined]
    return HttpResponse()


# --- 3. An app's own request class, composed with the mixin ------------------


class Tenant:
    name: str


class AppRequest(DBSCRequestMixin, HttpRequest):
    tenant: Tenant


def app_view(request: AppRequest) -> HttpResponse:
    assert_type(request.dbsc, DBSCState)
    assert_type(request.tenant, Tenant)
    assert_type(get_dbsc_state(request), DBSCState)
    return HttpResponse()


# --- @dbsc_exempt keeps the view's signature ----------------------------------


@dbsc_exempt
def exempt_view(request: HttpRequest, pk: int) -> HttpResponse:
    return HttpResponse(str(pk))


def call_exempt(request: HttpRequest) -> None:
    assert_type(exempt_view(request, 1), HttpResponse)
    exempt_view(request, "1")  # type: ignore[arg-type]


# --- Settings ----------------------------------------------------------------

DBSC: DBSCConfig = {"BOUND_COOKIE_AGE": 300, "ENFORCEMENT": "off"}
BAD_VALUE: DBSCConfig = {"ENFORCEMENT": "sometimes"}  # type: ignore[typeddict-item]
BAD_KEY: DBSCConfig = {"ENFORCMENT": "off"}  # type: ignore[typeddict-unknown-key]

# --- All three view styles are valid URL targets ------------------------------

urlpatterns: list[URLPattern] = [
    path("plain/", plain_view),
    path("dbsc/", dbsc_view),
    path("app/", app_view),
    path("exempt/<int:pk>/", exempt_view),
]
