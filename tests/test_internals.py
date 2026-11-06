"""Edge cases in the middleware, settings, session binding, challenges and cookies."""

import pytest
from django.contrib.sessions.backends.base import SessionBase
from django.core import signing
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse
from django.test import Client, RequestFactory, override_settings

from django_device_bound_sessions.api import DeviceBinding, get_binding
from django_device_bound_sessions.challenges import (
    REFRESH_SALT,
    REGISTRATION_SALT,
    ChallengeError,
    check_refresh_challenge,
    check_registration_challenge,
)
from django_device_bound_sessions.conf import BINDING_KEY, dbsc_settings
from django_device_bound_sessions.cookies import credential_attributes
from django_device_bound_sessions.middleware import DeviceBoundSessionMiddleware
from django_device_bound_sessions.testing import DBSCBrowser

pytestmark = pytest.mark.django_db


# --- Async views -------------------------------------------------------------


def test_async_view_is_anonymous_without_bound_cookie(registered, client):
    """request.auser() must be covered by enforcement, not just request.user."""
    assert client.get("/async/").json() == {"user": "alice", "bound": True}
    registered.expire_bound_cookie()
    assert client.get("/async/").json() == {"user": None, "bound": False}


def test_async_view_with_stolen_session_cookie(registered, client):
    thief = Client()
    thief.cookies["sessionid"] = client.cookies["sessionid"].value
    assert thief.get("/async/").json()["user"] is None


# --- Middleware configuration -------------------------------------------------


def test_middleware_requires_session_middleware():
    middleware = DeviceBoundSessionMiddleware(lambda request: HttpResponse())
    with pytest.raises(ImproperlyConfigured, match="SessionMiddleware"):
        middleware(RequestFactory().get("/"))


@override_settings(DBSC={"ENFORCEMENT": "sometimes"})
def test_unknown_enforcement_mode_fails_loudly(registered, client):
    registered.expire_bound_cookie()
    with pytest.raises(ImproperlyConfigured, match="ENFORCEMENT"):
        client.get("/")


def test_unknown_setting_name():
    with pytest.raises(AttributeError, match="Unknown DBSC setting"):
        dbsc_settings.NOT_A_SETTING  # noqa: B018


def test_setting_override_and_default():
    assert dbsc_settings.BOUND_COOKIE_AGE == 600
    with override_settings(DBSC={"BOUND_COOKIE_AGE": 30}):
        assert dbsc_settings.BOUND_COOKIE_AGE == 30


# --- Session binding ---------------------------------------------------------


def test_get_binding(registered, client):
    request = HttpRequest()
    request.session = client.session
    binding = get_binding(request)
    assert binding is not None
    assert binding.session_id == registered.session_id
    assert get_binding(_request_with_session({})) is None


@pytest.mark.parametrize(
    "stored",
    [
        "not-a-dict",
        {"id": "x"},  # missing fields
        {"id": "x", "alg": "ES256", "jwk": {}, "thumbprint": "t", "created_at": "not-a-date"},
    ],
)
def test_corrupt_binding_is_treated_as_unbound(stored):
    assert DeviceBinding.from_session(_session_with({BINDING_KEY: stored})) is None


def test_corrupt_binding_does_not_lock_out_the_session(client, user):
    """A garbled binding behaves like no binding: the session keeps working."""
    client.force_login(user)
    session = client.session
    session[BINDING_KEY] = {"id": "x"}
    session.save()
    assert client.get("/").json()["user"] == "alice"


def _session_with(data: dict[str, object]) -> SessionBase:
    session = SessionBase()
    session.update(data)
    return session


def _request_with_session(data: dict[str, object]) -> HttpRequest:
    request = HttpRequest()
    request.session = _session_with(data)
    return request


# --- Challenges ----------------------------------------------------------------


def test_garbage_challenge_is_rejected():
    with pytest.raises(ChallengeError, match="Invalid challenge"):
        check_refresh_challenge("session-id", "garbage")


def test_challenge_payload_must_be_an_object():
    challenge = signing.dumps("just a string", salt=REFRESH_SALT)
    with pytest.raises(ChallengeError, match="Invalid challenge"):
        check_refresh_challenge("session-id", challenge)


def test_challenges_are_not_interchangeable():
    """A registration challenge is useless as a refresh challenge, and vice versa."""
    registration = signing.dumps({"n": "nonce"}, salt=REGISTRATION_SALT)
    with pytest.raises(ChallengeError):
        check_refresh_challenge("session-id", registration)
    refresh = signing.dumps({"s": "session-id", "n": "nonce"}, salt=REFRESH_SALT)
    with pytest.raises(ChallengeError):
        check_registration_challenge(_session_with({}), refresh)


# --- Cookie attributes ---------------------------------------------------------


@override_settings(
    DBSC={
        "BOUND_COOKIE_SECURE": False,
        "BOUND_COOKIE_HTTPONLY": False,
        "BOUND_COOKIE_SAMESITE": None,
    }
)
def test_credential_attributes_minimal():
    assert credential_attributes() == "Path=/"


@override_settings(DBSC={"BOUND_COOKIE_DOMAIN": "example.com", "BOUND_COOKIE_SAMESITE": "Strict"})
def test_credential_attributes_match_the_set_cookie(client, user):
    """The attributes we announce must match the cookie we actually set."""
    browser = DBSCBrowser(client)
    client.force_login(user)
    browser.get("/")
    morsel = client.cookies["dbsc_bound"]
    assert morsel["domain"] == "example.com"
    assert morsel["samesite"] == "Strict"
    assert morsel["secure"]
    assert morsel["httponly"]
    assert browser.session_config["credentials"][0]["attributes"] == (
        "Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict"
    )


# --- The DBSCBrowser test helper's own guard rails ---------------------------


def test_browser_rejects_unknown_algorithm(client):
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        DBSCBrowser(client, algorithm="EdDSA")  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]


def test_browser_guards_before_registration(client):
    browser = DBSCBrowser(client)
    with pytest.raises(RuntimeError, match="No pending registration"):
        browser.register()
    with pytest.raises(RuntimeError, match="Not registered"):
        browser.refresh()
    with pytest.raises(RuntimeError, match="Not registered"):
        browser.session_config  # noqa: B018
