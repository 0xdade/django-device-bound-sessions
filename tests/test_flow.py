import time

import pytest
from django.contrib.auth.models import User
from django.core import signing
from django.test import Client, override_settings

from django_device_bound_sessions import sf
from django_device_bound_sessions.api import (
    CHALLENGE_HEADER,
    REGISTRATION_HEADER,
    RESPONSE_HEADER,
    SESSION_ID_HEADER,
    DeviceBinding,
)
from django_device_bound_sessions.challenges import REGISTRATION_SALT, new_refresh_challenge
from django_device_bound_sessions.proof import jwk_thumbprint
from django_device_bound_sessions.testing import DBSCBrowser

pytestmark = pytest.mark.django_db


def binding_of(client: Client) -> DeviceBinding:
    """The client's binding; fails the test if there isn't one."""
    binding = DeviceBinding.from_session(client.session)
    assert binding is not None, "session has no device binding"
    return binding


def has_binding(client: Client) -> bool:
    return DeviceBinding.from_session(client.session) is not None


def refresh_headers(browser: DBSCBrowser, proof: str | None = None) -> dict[str, str]:
    assert browser.session_id
    headers = {SESSION_ID_HEADER: sf.serialize_string(browser.session_id)}
    if proof:
        headers[RESPONSE_HEADER] = sf.serialize_string(proof)
    return headers


# --- registration offer ---------------------------------------------------


def test_no_offer_for_anonymous(client):
    assert REGISTRATION_HEADER not in client.get("/").headers


def test_offer_after_login(client, user):
    client.force_login(user)
    response = client.get("/")
    [(algs, params)] = sf.parse_list(response.headers[REGISTRATION_HEADER])
    assert isinstance(algs, list)
    assert [a for a, _ in algs] == ["ES256", "RS256"]
    assert params["path"] == "/dbsc/register/"
    assert params["challenge"]
    # Offered once only.
    assert REGISTRATION_HEADER not in client.get("/").headers


def test_offer_waits_for_non_redirect(client, user):
    client.force_login(user)
    assert REGISTRATION_HEADER not in client.get("/redirect/").headers
    assert REGISTRATION_HEADER in client.get("/").headers


@override_settings(DBSC={"OFFER_ON_LOGIN": False})
def test_offer_on_login_disabled(client, user):
    client.force_login(user)
    assert REGISTRATION_HEADER not in client.get("/").headers


# --- registration ---------------------------------------------------------


@pytest.mark.parametrize("algorithm", ["ES256", "RS256"])
def test_registration(client, user, algorithm):
    browser = DBSCBrowser(client, algorithm=algorithm)
    client.force_login(user)
    browser.get("/")

    config = browser.session_config
    assert config["refresh_url"] == "/dbsc/refresh/"
    assert config["scope"] == {"include_site": False}
    assert config["credentials"] == [
        {
            "type": "cookie",
            "name": "dbsc_bound",
            "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax",
        }
    ]
    stored = binding_of(client)
    assert stored.session_id == browser.session_id
    assert stored.algorithm == algorithm
    assert "d" not in stored.public_key
    assert stored.thumbprint
    assert stored.created_at is not None
    assert stored.last_refreshed_at is None
    assert browser.has_bound_cookie()
    assert browser.challenge, "registration should pre-seed a refresh challenge"

    assert client.get("/").json() == {
        "user": "alice",
        "dbsc_session": browser.session_id,
        "bound": True,
    }


def offered(client: Client, user: User) -> tuple[DBSCBrowser, str, str]:
    browser = DBSCBrowser(client, auto_register=False)
    client.force_login(user)
    browser.get("/")
    assert browser.pending_registration
    path, challenge = browser.pending_registration
    assert challenge
    return browser, path, challenge


def test_registration_requires_login(client):
    browser = DBSCBrowser(client)
    response = client.post(
        "/dbsc/register/",
        headers={RESPONSE_HEADER: browser.make_proof("x", include_jwk=True)},
    )
    assert response.status_code == 401


def test_registration_rejects_forged_challenge(client, user):
    browser, path, _ = offered(client, user)
    forged = signing.dumps({"n": "guess"}, salt=REGISTRATION_SALT)
    response = client.post(
        path, headers={RESPONSE_HEADER: browser.make_proof(forged, include_jwk=True)}
    )
    assert response.status_code == 400
    assert not has_binding(client)


def test_registration_challenge_is_single_use(client, user):
    browser, path, challenge = offered(client, user)
    proof = browser.make_proof(challenge, include_jwk=True)
    assert client.post(path, headers={RESPONSE_HEADER: proof}).status_code == 200
    # Drop the binding so the replay reaches the challenge check, not the
    # already-bound check.
    session = client.session
    del session["_dbsc"]
    session.save()
    assert client.post(path, headers={RESPONSE_HEADER: proof}).status_code == 400


def test_registration_challenge_from_other_session(user):
    a, b = Client(), Client()
    _, _, challenge_a = offered(a, user)
    browser_b, path, _ = offered(b, user)
    proof = browser_b.make_proof(challenge_a, include_jwk=True)
    assert b.post(path, headers={RESPONSE_HEADER: proof}).status_code == 400


def test_registration_rejects_missing_jwk(client, user):
    browser, path, challenge = offered(client, user)
    proof = browser.make_proof(challenge, include_jwk=False)
    assert client.post(path, headers={RESPONSE_HEADER: proof}).status_code == 400


def test_registration_rejects_bad_signature(client, user):
    browser, path, challenge = offered(client, user)
    other = DBSCBrowser(Client())
    # jwk header is browser's key, but signed by another key.
    proof = browser.make_proof(challenge, include_jwk=True, key=other.private_key)
    assert client.post(path, headers={RESPONSE_HEADER: proof}).status_code == 400


def test_registration_rejects_wrong_typ(client, user):
    import jwt

    browser, path, challenge = offered(client, user)
    proof = jwt.encode(
        {"jti": challenge},
        browser.private_key,
        algorithm="ES256",
        headers={"typ": "JWT", "jwk": browser.public_jwk},
    )
    assert client.post(path, headers={RESPONSE_HEADER: proof}).status_code == 400


def test_registration_rejects_alg_none(client, user):
    import base64
    import json

    _, path, challenge = offered(client, user)

    def b64(obj: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    proof = f"{b64({'alg': 'none', 'typ': 'dbsc+jwt'})}.{b64({'jti': challenge})}."
    assert client.post(path, headers={RESPONSE_HEADER: proof}).status_code == 400


@override_settings(DBSC={"ALGORITHMS": ["ES256"]})
def test_registration_rejects_disallowed_algorithm(client, user):
    browser = DBSCBrowser(client, algorithm="RS256", auto_register=False)
    client.force_login(user)
    response = client.get("/")
    assert "RS256" not in response.headers[REGISTRATION_HEADER]
    _, params = sf.parse_list(response.headers[REGISTRATION_HEADER])[0]
    assert isinstance(params["challenge"], str)
    assert isinstance(params["path"], str)
    proof = browser.make_proof(params["challenge"], include_jwk=True)
    assert client.post(params["path"], headers={RESPONSE_HEADER: proof}).status_code == 400


def test_registration_accepts_unquoted_proof(client, user):
    browser, path, challenge = offered(client, user)
    proof = browser.make_proof(challenge, include_jwk=True)
    assert client.post(path, headers={RESPONSE_HEADER: proof}).status_code == 200


# --- enforcement ----------------------------------------------------------


def test_missing_bound_cookie_is_anonymous(registered, client):
    registered.expire_bound_cookie()
    body = client.get("/").json()
    assert body["user"] is None
    assert body["bound"] is False


def test_stolen_session_cookie_is_useless(registered, client):
    thief = Client()
    thief.cookies["sessionid"] = client.cookies["sessionid"].value
    assert thief.get("/").json()["user"] is None


def test_tampered_bound_cookie_is_rejected(registered, client):
    client.cookies["dbsc_bound"] = client.cookies["dbsc_bound"].value + "x"
    assert client.get("/").json()["user"] is None


def test_bound_cookie_from_other_session_is_rejected(registered, client, user):
    other = Client()
    other_browser = DBSCBrowser(other)
    other.force_login(user)
    other_browser.get("/")
    client.cookies["dbsc_bound"] = other.cookies["dbsc_bound"].value
    assert client.get("/").json()["user"] is None


def test_expired_bound_cookie_is_rejected(registered, client):
    with override_settings(DBSC={"BOUND_COOKIE_AGE": 0, "BOUND_COOKIE_GRACE": 0}):
        time.sleep(1.1)
        assert client.get("/").json()["user"] is None


def test_exempt_view_skips_enforcement(registered, client):
    registered.expire_bound_cookie()
    assert client.get("/exempt/").json()["user"] == "alice"


@override_settings(DBSC={"ENFORCEMENT": "off"})
def test_enforcement_off(registered, client):
    registered.expire_bound_cookie()
    assert client.get("/").json() == {
        "user": "alice",
        "dbsc_session": registered.session_id,
        "bound": False,
    }


@override_settings(DBSC={"ENFORCEMENT": "logout"})
def test_enforcement_logout(registered, client):
    registered.expire_bound_cookie()
    assert client.get("/").json()["user"] is None
    assert not has_binding(client)
    # The session is gone for good, even with the bound cookie restored.
    assert client.get("/exempt/").json()["user"] is None


def test_unbound_sessions_are_not_affected(client, user):
    """Browsers without DBSC support keep working as before."""
    client.force_login(user)
    client.get("/")  # offer ignored
    assert client.get("/").json()["user"] == "alice"


# --- refresh --------------------------------------------------------------


def test_refresh_round_trip(registered, client):
    registered.challenge = None  # force the 403 challenge flow
    registered.expire_bound_cookie()
    body = registered.get("/").json()
    assert body["user"] == "alice"
    assert body["bound"] is True

    first, second = registered.last_refresh_responses
    assert first.status_code == 403
    _value, params = sf.parse_list(first.headers[CHALLENGE_HEADER])[0]
    assert params == {"id": registered.session_id}
    assert second.status_code == 200
    assert second.json()["session_identifier"] == registered.session_id
    assert binding_of(client).last_refreshed_at is not None


def test_refresh_uses_cached_challenge(registered):
    registered.expire_bound_cookie()
    assert registered.get("/").json()["bound"] is True
    assert [r.status_code for r in registered.last_refresh_responses] == [200]


def test_repeated_refreshes(registered):
    for _ in range(3):
        registered.expire_bound_cookie()
        assert registered.get("/").json()["bound"] is True


def test_refresh_rejects_other_key(registered, client):
    challenge = new_refresh_challenge(registered.session_id)
    attacker = DBSCBrowser(Client())
    proof = attacker.make_proof(challenge)
    response = client.post("/dbsc/refresh/", headers=refresh_headers(registered, proof))
    assert response.status_code == 400
    assert "dbsc_bound" not in response.cookies
    # Legitimate device is unaffected.
    assert binding_of(client).session_id == registered.session_id


def test_refresh_replay_gets_new_challenge(registered, client):
    challenge = new_refresh_challenge(registered.session_id)
    proof = registered.make_proof(challenge)
    assert (
        client.post("/dbsc/refresh/", headers=refresh_headers(registered, proof)).status_code == 200
    )
    replay = client.post("/dbsc/refresh/", headers=refresh_headers(registered, proof))
    assert replay.status_code == 403
    assert CHALLENGE_HEADER in replay.headers


def test_refresh_challenge_for_other_session_rejected(registered, client):
    proof = registered.make_proof(new_refresh_challenge("someone-else"))
    response = client.post("/dbsc/refresh/", headers=refresh_headers(registered, proof))
    assert response.status_code == 400


def test_stale_refresh_challenge_gets_new_challenge(registered, client):
    challenge = new_refresh_challenge(registered.session_id)
    with override_settings(DBSC={"CHALLENGE_MAX_AGE": 0}):
        time.sleep(1.1)
        response = client.post(
            "/dbsc/refresh/", headers=refresh_headers(registered, registered.make_proof(challenge))
        )
    assert response.status_code == 403


def test_refresh_requires_session_id_header(registered, client):
    assert client.post("/dbsc/refresh/").status_code == 400


def test_refresh_unknown_session_terminates(registered, client):
    response = client.post(
        "/dbsc/refresh/", headers={SESSION_ID_HEADER: sf.serialize_string("nope")}
    )
    assert response.status_code == 200
    assert response.json() == {"continue": False}


def test_refresh_without_session_cookie_terminates(registered, client):
    """Without the Django session there is no binding to refresh."""
    other = Client()
    response = other.post("/dbsc/refresh/", headers=refresh_headers(registered))
    assert response.json() == {"continue": False}
    # ...and the real session is untouched.
    assert binding_of(client).session_id == registered.session_id


def test_refresh_is_csrf_exempt(registered, user):
    client = registered.client
    client.handler.enforce_csrf_checks = True
    registered.expire_bound_cookie()
    assert registered.get("/").json()["bound"] is True


def test_refresh_requires_post(registered, client):
    assert client.get("/dbsc/refresh/").status_code == 405


# --- logout / lifecycle ---------------------------------------------------


def test_logout_terminates(registered, client):
    client.get("/logout/")
    assert not has_binding(client)
    registered.expire_bound_cookie()
    response = registered.refresh()
    assert response.json() == {"continue": False}
    assert registered.config is None


# --- binding is permanent: a stolen cookie can't move the session ---------


def thief_of(client: Client) -> Client:
    thief = Client()
    thief.cookies["sessionid"] = client.cookies["sessionid"].value
    return thief


def test_bound_session_is_never_offered_again(registered, client, user):
    thief = thief_of(client)
    for path in ("/", "/exempt/", "/redirect/"):
        assert REGISTRATION_HEADER not in thief.get(path).headers
    # Even an explicit offer (or a same-user re-login) is ignored once bound.
    client.force_login(user)
    assert REGISTRATION_HEADER not in thief.get("/").headers
    assert REGISTRATION_HEADER not in client.get("/").headers


def test_thief_cannot_rebind_with_valid_challenge(registered, client):
    """Belt and braces: even with a genuine challenge, rebinding is refused."""
    from django_device_bound_sessions.challenges import new_registration_challenge

    thief = thief_of(client)
    session = thief.session
    challenge = new_registration_challenge(session)
    session.save()
    attacker = DBSCBrowser(thief)
    response = thief.post(
        "/dbsc/register/",
        headers={RESPONSE_HEADER: attacker.make_proof(challenge, include_jwk=True)},
    )
    assert response.status_code == 409
    assert "dbsc_bound" not in response.cookies
    assert binding_of(client).session_id == registered.session_id
    assert binding_of(client).thumbprint == jwk_thumbprint(registered.public_jwk)
    assert binding_of(client).thumbprint != jwk_thumbprint(attacker.public_jwk)
    # The legitimate device keeps working.
    registered.expire_bound_cookie()
    assert registered.get("/").json()["bound"] is True


def test_thief_cannot_rebind_with_forged_challenge(registered, client):
    thief = thief_of(client)
    attacker = DBSCBrowser(thief)
    forged = signing.dumps({"n": "guess"}, salt=REGISTRATION_SALT)
    response = thief.post(
        "/dbsc/register/", headers={RESPONSE_HEADER: attacker.make_proof(forged, include_jwk=True)}
    )
    assert response.status_code == 409


def test_unused_offer_expires(client, user):
    """An offer left pending (e.g. tab closed after the login redirect) must
    not be handed to whoever shows up with the cookie later."""
    client.force_login(user)
    assert REGISTRATION_HEADER not in client.get("/redirect/").headers
    thief = thief_of(client)
    with override_settings(DBSC={"OFFER_MAX_AGE": 0}):
        time.sleep(1.1)
        assert REGISTRATION_HEADER not in thief.get("/").headers
    # And it's gone for good, not just deferred.
    assert REGISTRATION_HEADER not in client.get("/").headers


def test_offer_within_window(client, user):
    client.force_login(user)
    client.get("/redirect/")
    with override_settings(DBSC={"OFFER_MAX_AGE": 60}):
        assert REGISTRATION_HEADER in client.get("/").headers


@override_settings(
    DBSC={
        "SCOPE_INCLUDE_SITE": True,
        "SCOPE_ORIGIN": "https://example.com",
        "SCOPE_SPECIFICATION": [{"type": "exclude", "domain": "*", "path": "/static"}],
        "BOUND_COOKIE_DOMAIN": "example.com",
        "BOUND_COOKIE_NAME": "__Secure-auth",
        "ALLOWED_REFRESH_INITIATORS": ["*.example.com"],
    }
)
def test_custom_session_config(client, user):
    browser = DBSCBrowser(client)
    client.force_login(user)
    browser.get("/")
    assert browser.session_config["scope"] == {
        "include_site": True,
        "origin": "https://example.com",
        "scope_specification": [{"type": "exclude", "domain": "*", "path": "/static"}],
    }
    assert browser.session_config["credentials"][0] == {
        "type": "cookie",
        "name": "__Secure-auth",
        "attributes": "Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax",
    }
    assert browser.session_config["allowed_refresh_initiators"] == ["*.example.com"]


# --- get_dbsc_state (for views typed against plain HttpRequest) -----------


def test_get_dbsc_state_matches_request_attribute(registered, client):
    from django.http import HttpRequest, JsonResponse
    from django.test import RequestFactory

    from django_device_bound_sessions.api import DBSCState, get_dbsc_state
    from django_device_bound_sessions.middleware import DeviceBoundSessionMiddleware

    seen: list[DBSCState] = []

    def view(request: HttpRequest) -> JsonResponse:
        seen.append(get_dbsc_state(request))
        return JsonResponse({})

    middleware = DeviceBoundSessionMiddleware(view)
    request = RequestFactory().get("/")
    request.session = client.session
    request.COOKIES = {k: m.value for k, m in client.cookies.items()}
    middleware(request)
    assert seen
    # getattr: HttpRequest is (correctly) not typed as having .dbsc.
    assert seen[0] is getattr(request, "dbsc")  # noqa: B009
    assert seen[0].bound
    assert seen[0].session_id == registered.session_id


def test_get_dbsc_state_without_middleware_fails_loudly():
    from django.core.exceptions import ImproperlyConfigured
    from django.test import RequestFactory

    from django_device_bound_sessions.api import get_dbsc_state

    with pytest.raises(ImproperlyConfigured, match="DeviceBoundSessionMiddleware"):
        get_dbsc_state(RequestFactory().get("/"))
