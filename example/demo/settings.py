"""Demo project for django-device-bound-sessions. Run with: uv run example/manage.py runserver"""

from pathlib import Path

from django_device_bound_sessions.conf import DBSCConfig

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "django-device-bound-sessions-demo-not-secret"  # noqa: S105 - demo only, never deploy
DEBUG = True
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_device_bound_sessions",
    "demo",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_device_bound_sessions.middleware.DeviceBoundSessionMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "demo.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}

USE_TZ = True
STATIC_URL = "static/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

DBSC: DBSCConfig = {
    # Short lifetime so you can watch Chrome refresh in DevTools.
    "BOUND_COOKIE_AGE": 60,
    "SCOPE_SPECIFICATION": [{"type": "exclude", "domain": "*", "path": "/static"}],
}

# The demo runs as a single runserver process, so Django's default per-process
# LocMemCache is fine as the replay cache. Deployments with several workers
# need a shared cache (see the README's security notes).
SILENCED_SYSTEM_CHECKS = ["django_device_bound_sessions.W001"]

LOGGING = {
    "version": 1,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {"django_device_bound_sessions": {"handlers": ["console"], "level": "INFO"}},
}
