"""Settings for django-device-bound-sessions.

Configure via a ``DBSC`` dict in your Django settings, e.g.::

    DBSC = {
        "BOUND_COOKIE_AGE": 300,
        "ENFORCEMENT": "anonymous",
    }

Values are read on every access so ``override_settings`` works in tests.
"""

from typing import Any, Literal, NotRequired, TypedDict

from django.conf import settings


class ScopeRule(TypedDict):
    """One entry of ``scope.scope_specification``."""

    type: Literal["include", "exclude"]
    domain: NotRequired[str]
    path: NotRequired[str]


class DBSCConfig(TypedDict, total=False):
    """Shape of the ``DBSC`` setting. Annotate yours to have it checked::

    from django_device_bound_sessions.conf import DBSCConfig

    DBSC: DBSCConfig = {"BOUND_COOKIE_AGE": 300}
    """

    BOUND_COOKIE_NAME: str
    BOUND_COOKIE_AGE: int
    BOUND_COOKIE_GRACE: int
    BOUND_COOKIE_DOMAIN: str | None
    BOUND_COOKIE_PATH: str
    BOUND_COOKIE_SECURE: bool
    BOUND_COOKIE_HTTPONLY: bool
    BOUND_COOKIE_SAMESITE: Literal["Lax", "Strict", "None"] | None
    ALGORITHMS: list[Literal["ES256", "RS256"]]
    CHALLENGE_MAX_AGE: int
    CACHE_ALIAS: str
    REGISTRATION_PATH: str | None
    REFRESH_PATH: str | None
    SCOPE_ORIGIN: str | None
    SCOPE_INCLUDE_SITE: bool
    SCOPE_SPECIFICATION: list[ScopeRule]
    ALLOWED_REFRESH_INITIATORS: list[str]
    OFFER_ON_LOGIN: bool
    OFFER_MAX_AGE: int
    ENFORCEMENT: Literal["anonymous", "logout", "off"]


DEFAULTS: DBSCConfig = {
    # --- Bound (short-lived) cookie --------------------------------------
    "BOUND_COOKIE_NAME": "dbsc_bound",
    # Lifetime in seconds. When it expires, the browser refreshes it by
    # proving possession of the device-bound key.
    "BOUND_COOKIE_AGE": 600,
    # Extra seconds the server accepts past BOUND_COOKIE_AGE (clock skew,
    # requests already in flight when the cookie expired).
    "BOUND_COOKIE_GRACE": 30,
    "BOUND_COOKIE_DOMAIN": None,
    "BOUND_COOKIE_PATH": "/",
    "BOUND_COOKIE_SECURE": True,
    "BOUND_COOKIE_HTTPONLY": True,
    "BOUND_COOKIE_SAMESITE": "Lax",
    # --- Protocol ---------------------------------------------------------
    # Algorithms offered in Secure-Session-Registration, in preference order.
    # "none" is intentionally not supported.
    "ALGORITHMS": ["ES256", "RS256"],
    # How long (seconds) a registration/refresh challenge stays valid.
    "CHALLENGE_MAX_AGE": 300,
    # Cache alias used to make challenges single-use (replay protection).
    "CACHE_ALIAS": "default",
    # --- Session configuration sent to the browser -----------------------
    # Override the endpoint URLs (otherwise resolved from django_device_bound_sessions.urls).
    "REGISTRATION_PATH": None,
    "REFRESH_PATH": None,
    # scope.origin; None lets the browser default it to the serving origin.
    "SCOPE_ORIGIN": None,
    # scope.include_site: True = whole site, False = this origin only.
    "SCOPE_INCLUDE_SITE": False,
    # scope.scope_specification, e.g.
    # [{"type": "exclude", "domain": "*", "path": "/static"}]
    "SCOPE_SPECIFICATION": [],
    "ALLOWED_REFRESH_INITIATORS": [],
    # --- Behaviour --------------------------------------------------------
    # Automatically offer DBSC registration after a successful login().
    "OFFER_ON_LOGIN": True,
    # Seconds a pending offer stays usable. Until a session is bound, anyone
    # holding its cookie could receive the offer, so keep this short: the
    # offer is meant for the page load right after login.
    "OFFER_MAX_AGE": 60,
    # What happens when a bound session arrives without a valid bound cookie:
    #   "anonymous" - treat this request as unauthenticated (default)
    #   "logout"    - log the session out entirely (also ends the DBSC session)
    #   "off"       - do nothing; inspect request.dbsc yourself
    "ENFORCEMENT": "anonymous",
}


# DEFAULTS is a TypedDict so its keys and values are checked; lookups by a
# runtime setting name go through this plain-dict copy instead.
_DEFAULTS_BY_NAME: dict[str, object] = dict(DEFAULTS)


class DBSCSettings:
    """Typed accessors for the ``DBSC`` settings dict, with defaults applied."""

    BOUND_COOKIE_NAME: str
    BOUND_COOKIE_AGE: int
    BOUND_COOKIE_GRACE: int
    BOUND_COOKIE_DOMAIN: str | None
    BOUND_COOKIE_PATH: str
    BOUND_COOKIE_SECURE: bool
    BOUND_COOKIE_HTTPONLY: bool
    BOUND_COOKIE_SAMESITE: Literal["Lax", "Strict", "None"] | None
    ALGORITHMS: list[str]
    CHALLENGE_MAX_AGE: int
    CACHE_ALIAS: str
    REGISTRATION_PATH: str | None
    REFRESH_PATH: str | None
    SCOPE_ORIGIN: str | None
    SCOPE_INCLUDE_SITE: bool
    SCOPE_SPECIFICATION: list[ScopeRule]
    ALLOWED_REFRESH_INITIATORS: list[str]
    OFFER_ON_LOGIN: bool
    OFFER_MAX_AGE: int
    ENFORCEMENT: Literal["anonymous", "logout", "off"]

    def __getattr__(self, name: str) -> Any:
        if name not in _DEFAULTS_BY_NAME:
            raise AttributeError(f"Unknown DBSC setting: {name}")
        configured: dict[str, Any] = getattr(settings, "DBSC", {})
        return configured.get(name, _DEFAULTS_BY_NAME[name])


dbsc_settings = DBSCSettings()

# Keys stored in request.session.
BINDING_KEY = "_dbsc"
OFFER_KEY = "_dbsc_offer"
REGISTRATION_NONCE_KEY = "_dbsc_registration_nonce"
