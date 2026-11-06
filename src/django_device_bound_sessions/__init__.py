"""Device Bound Session Credentials (DBSC) for Django.

See https://w3c.github.io/webappsec-dbsc/ for the protocol.
"""

from importlib.metadata import version

# Single source of truth is pyproject.toml.
__version__ = version("django-device-bound-sessions")
