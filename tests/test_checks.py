"""System checks: the replay cache must be shared by every worker."""

import pytest
from django.core import checks
from django.core.cache.backends.locmem import LocMemCache
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import override_settings

from django_device_bound_sessions.checks import E001, E002, W001, check_replay_cache


class CustomLocMemCache(LocMemCache):
    """A subclass is still per-process."""


def ids() -> list[str | None]:
    return [message.id for message in check_replay_cache(app_configs=None)]


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
def test_locmem_cache_warns():
    [message] = check_replay_cache(app_configs=None)
    assert message.id == W001
    assert message.level == checks.WARNING
    assert "LocMemCache" in message.msg
    assert W001 in (message.hint or "")  # tells you how to silence it


@override_settings(CACHES={"default": {"BACKEND": f"{__name__}.CustomLocMemCache"}})
def test_locmem_subclass_warns():
    assert ids() == [W001]


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.memcached.PyMemcacheCache"}}
)
def test_check_does_not_create_the_cache():
    """pymemcache isn't installed: creating this cache would fail, inspecting it doesn't."""
    assert ids() == []


@override_settings(CACHES={"default": {"BACKEND": "no.such.Backend"}})
def test_unimportable_backend_is_left_to_django():
    assert ids() == []


@override_settings(CACHES={"default": {"BACKEND": "django.utils.module_loading.import_string"}})
def test_backend_that_is_not_a_class_does_not_crash_the_check():
    assert ids() == []


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}})
def test_dummy_cache_is_an_error():
    [message] = check_replay_cache(app_configs=None)
    assert message.id == E002
    assert message.level == checks.ERROR
    assert "replay protection is disabled" in message.msg


@override_settings(DBSC={"CACHE_ALIAS": "replay"})
def test_unknown_cache_alias_is_an_error():
    [message] = check_replay_cache(app_configs=None)
    assert message.id == E001
    assert "'replay'" in message.msg


@pytest.mark.parametrize(
    "backend",
    [
        "django.core.cache.backends.db.DatabaseCache",
        "django.core.cache.backends.redis.RedisCache",
        "django.core.cache.backends.memcached.PyMemcacheCache",
    ],
)
def test_shared_caches_pass(backend):
    with override_settings(CACHES={"default": {"BACKEND": backend, "LOCATION": "replay"}}):
        assert ids() == []


@override_settings(
    CACHES={
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
        "replay": {"BACKEND": "django.core.cache.backends.db.DatabaseCache", "LOCATION": "t"},
    },
    DBSC={"CACHE_ALIAS": "replay"},
)
def test_only_the_configured_alias_is_checked():
    assert ids() == []


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}})
def test_manage_py_check_fails_on_dummy_cache():
    with pytest.raises(SystemCheckError, match="E002"):
        call_command("check")


def test_the_check_is_registered_and_silenced_in_test_settings():
    # tests/settings.py silences W001 (single process), so `check` passes.
    call_command("check")
    assert check_replay_cache in checks.registry.registry.get_checks()
