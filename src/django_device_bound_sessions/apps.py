from django.apps import AppConfig


class DjangoDBSCConfig(AppConfig):
    name = "django_device_bound_sessions"
    verbose_name = "Device Bound Session Credentials"

    def ready(self) -> None:
        # Imported for its side effect: connecting the signal receivers.
        from . import signals  # noqa: F401  # pyright: ignore[reportUnusedImport]
