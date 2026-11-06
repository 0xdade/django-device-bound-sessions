import pytest
from django.core.cache import cache
from django.test import Client

from django_device_bound_sessions.testing import DBSCBrowser


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create_user("alice", password="pw")


@pytest.fixture
def client():
    return Client()


@pytest.fixture
def browser(client):
    return DBSCBrowser(client)


@pytest.fixture
def registered(browser, client, user):
    """A logged-in browser that has completed DBSC registration."""
    client.force_login(user)
    browser.get("/")
    assert browser.session_id
    return browser
