SECRET_KEY = "django-device-bound-sessions-tests"
DEBUG = False
ALLOWED_HOSTS = ["testserver", "localhost"]
USE_TZ = True

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django_device_bound_sessions",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_device_bound_sessions.middleware.DeviceBoundSessionMiddleware",
]

ROOT_URLCONF = "tests.urls"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
# The test run is a single process, so a per-process replay cache is fine.
SILENCED_SYSTEM_CHECKS = ["django_device_bound_sessions.W001"]

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
