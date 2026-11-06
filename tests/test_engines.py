"""The binding lives in the session, so DBSC must work on every engine."""

import pytest
from django.test import Client, override_settings

from django_device_bound_sessions.testing import DBSCBrowser

ENGINES = [
    "django.contrib.sessions.backends.db",
    "django.contrib.sessions.backends.cache",
    "django.contrib.sessions.backends.cached_db",
    "django.contrib.sessions.backends.file",
    "django.contrib.sessions.backends.signed_cookies",
]


@pytest.mark.django_db
@pytest.mark.parametrize("algorithm", ["ES256", "RS256"])
@pytest.mark.parametrize("engine", ENGINES)
def test_full_flow(engine, algorithm, user, tmp_path):
    with override_settings(SESSION_ENGINE=engine, SESSION_FILE_PATH=str(tmp_path)):
        client = Client()
        browser = DBSCBrowser(client, algorithm=algorithm)
        client.force_login(user)
        assert browser.get("/").json()["user"] == "alice"
        assert browser.session_id

        browser.expire_bound_cookie()
        assert client.get("/").json()["user"] is None  # enforcement

        assert browser.get("/").json() == {
            "user": "alice",
            "dbsc_session": browser.session_id,
            "bound": True,
        }
        if engine.endswith("signed_cookies"):
            # Whole session (incl. public key) must fit in one cookie.
            assert len(client.cookies["sessionid"].value) < 4096

        # A stolen session cookie still doesn't work elsewhere.
        thief = Client()
        thief.cookies["sessionid"] = client.cookies["sessionid"].value
        assert thief.get("/").json()["user"] is None
