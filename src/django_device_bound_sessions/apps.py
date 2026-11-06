from django.apps import AppConfig


class DjangoDBSCConfig(AppConfig):
    name = "django_device_bound_sessions"
    verbose_name = "Device Bound Session Credentials"

    def ready(self) -> None:
        # Imported for their side effects: connecting the signal receivers and
        # registering the system checks.
        from . import checks, signals  # noqa: F401  # pyright: ignore[reportUnusedImport]
