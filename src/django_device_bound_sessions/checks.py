"""Django system checks for django-device-bound-sessions.

Run with ``manage.py check`` (and automatically by ``runserver``, ``migrate``
and the test runner). Silence one with ``SILENCED_SYSTEM_CHECKS``.
"""

from collections.abc import Sequence
from typing import Any

from django.apps import AppConfig
from django.conf import settings
from django.core import checks
from django.core.cache.backends.dummy import DummyCache
from django.core.cache.backends.locmem import LocMemCache
from django.utils.module_loading import import_string

from .conf import dbsc_settings

#: CACHE_ALIAS names a cache that isn't in CACHES.
E001 = "django_device_bound_sessions.E001"
#: The replay cache is a DummyCache, so replay protection is disabled.
E002 = "django_device_bound_sessions.E002"
#: The replay cache is per-process (LocMemCache).
W001 = "django_device_bound_sessions.W001"

_SHARED_CACHE_HINT = (
    "Point DBSC['CACHE_ALIAS'] at a cache every worker shares, with an atomic add(), "
    "such as Redis, Memcached or django.core.cache.backends.db.DatabaseCache."
)


@checks.register(checks.Tags.caches, checks.Tags.security)
def check_replay_cache(
    app_configs: Sequence[AppConfig] | None, **kwargs: Any
) -> list[checks.CheckMessage]:
    """The cache that makes challenges single-use must be shared by every worker.

    Looks at the configured backend *class* without creating the cache, so the
    check never connects anywhere or needs the backend's client library.
    """
    alias = dbsc_settings.CACHE_ALIAS
    config = settings.CACHES.get(alias)
    if config is None:
        return [
            checks.Error(
                f"DBSC['CACHE_ALIAS'] is {alias!r}, which is not a cache in CACHES.",
                hint=_SHARED_CACHE_HINT,
                id=E001,
            )
        ]
    try:
        backend = import_string(config.get("BACKEND", ""))
    except ImportError:
        # A misnamed backend fails loudly as soon as the cache is used.
        return []
    if not isinstance(backend, type):
        return []
    if issubclass(backend, DummyCache):
        return [
            checks.Error(
                f"The DBSC replay cache {alias!r} is a DummyCache, so replay protection "
                "is disabled: its add() always succeeds, and a used proof can be replayed.",
                hint=_SHARED_CACHE_HINT,
                id=E002,
            )
        ]
    if issubclass(backend, LocMemCache):
        return [
            checks.Warning(
                f"The DBSC replay cache {alias!r} is a LocMemCache, which each process "
                "keeps separately. With more than one worker, a used proof can be "
                "replayed on another worker until its challenge expires.",
                hint=_SHARED_CACHE_HINT + f" If you only ever run one process, silence {W001}.",
                id=W001,
            )
        ]
    return []
