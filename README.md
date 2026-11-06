# django-device-bound-sessions

[Device Bound Session Credentials](https://developer.chrome.com/docs/web-platform/device-bound-session-credentials)
(DBSC) for Django. If someone steals a user's session cookie, it stops working on any other device.

## How it works

With DBSC, a supporting browser (Chrome) creates a key pair in the device's secure hardware when a
user logs in. The private key never leaves the device. The library adds a second, **short-lived
"bound" cookie** alongside Django's normal session cookie. A browser can only get a new bound cookie
by signing a server challenge with that key.

```
login ──► response carries  Secure-Session-Registration: (ES256 RS256);path="/dbsc/register/";challenge="…"
browser ──► POST /dbsc/register/   Secure-Session-Response: <JWT signed by new key, includes public JWK>
server  ◄── session config JSON + Set-Cookie: dbsc_bound=…; Max-Age=600

…bound cookie expires…
browser ──► POST /dbsc/refresh/   Sec-Secure-Session-Id: "<id>"
server  ◄── 403  Secure-Session-Challenge: "<challenge>";id="<id>"
browser ──► POST /dbsc/refresh/   Sec-Secure-Session-Id + Secure-Session-Response: <JWT over challenge>
server  ◄── 200  Set-Cookie: dbsc_bound=…
```

Once a Django session is bound, the middleware rejects any request that lacks a valid bound cookie
(by default it treats the request as anonymous). An attacker holding only `sessionid` has no key, so
they can't refresh and are locked out within `BOUND_COOKIE_AGE` seconds.

Browsers without DBSC support ignore the registration header. Their sessions never become bound and
keep working exactly as they do today.

There is no database model. The device binding (public key, algorithm, and audit fields) is stored
in the Django session itself, so:

- it works with any `SESSION_ENGINE` (db, cache, cached_db, file, signed_cookies);
- it lives exactly as long as the session does. Logging out or flushing the session removes the
  binding, and the browser's next refresh gets `{"continue": false}`.

## Installation

Requires Python 3.12+ and Django 5.2 (LTS) or 6.1+.

```bash
pip install django-device-bound-sessions
```

```python
INSTALLED_APPS = [
    ...,
    "django_device_bound_sessions",
]

MIDDLEWARE = [
    ...,
    "django.contrib.sessions.middleware.SessionMiddleware",
    ...,
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_device_bound_sessions.middleware.DeviceBoundSessionMiddleware",  # after auth
    ...,
]
```

```python
# urls.py
urlpatterns = [
    ...,
    path("dbsc/", include("django_device_bound_sessions.urls")),
]
```

That's it: no migrations. Any `django.contrib.auth.login()` call offers DBSC registration on the next non-redirect
response.

## Using it in views

Every request gets `request.dbsc`:

| attribute | meaning |
|---|---|
| `request.dbsc.binding` | `DeviceBinding` for this session, or `None` |
| `request.dbsc.session_id` | DBSC session id, or `None` |
| `request.dbsc.registered` | the session has a binding |
| `request.dbsc.bound` | request carried a valid bound cookie |

A `DeviceBinding` has `session_id`, `algorithm`, `public_key` (JWK), `thumbprint` (RFC 7638),
`user_agent`, `created_at`, and `last_refreshed_at`.

Helpers:

```python
from django_device_bound_sessions.api import get_binding, offer_registration
from django_device_bound_sessions.decorators import dbsc_exempt

offer_registration(request)  # offer DBSC outside of login (e.g. after step-up auth)
get_binding(request)  # the DeviceBinding, also available as request.dbsc.binding


@dbsc_exempt  # skip enforcement and offers for this view
def health(request): ...
```

To end a binding, end the session (`logout()`, `request.session.flush()`).

## Type checking

The package ships `py.typed` and is checked with mypy (strict, with django-stubs), pyright (strict)
and [ty](https://docs.astral.sh/ty/). You don't have to change how your views are typed. Pick whichever of these fits your code:

```python
from django.http import HttpRequest
from django_device_bound_sessions.api import DBSCHttpRequest, DBSCRequestMixin, get_dbsc_state


# 1. Views typed against plain HttpRequest: nothing to change.
def account(request: HttpRequest) -> HttpResponse:
    state = get_dbsc_state(request)  # DBSCState
    if state.binding is not None:
        ...


# 2. Use DBSCHttpRequest to access request.dbsc directly.
def account(request: DBSCHttpRequest) -> HttpResponse:
    if request.dbsc.bound:
        ...


# 3. Already have your own request type? Add the mixin to it.
class AppRequest(DBSCRequestMixin, HttpRequest):
    tenant: Tenant
```

If the middleware isn't installed, `get_dbsc_state()` raises `ImproperlyConfigured` instead of
quietly reporting an unbound session. `get_binding(request)` reads the session directly and works
without the middleware.

`typecheck/downstream.py` pins these types down for apps using the library. mypy, pyright and ty all
check it strictly, so a change that loosens or breaks them fails the check.

Annotate your settings with `DBSCConfig` to get misspelled keys and wrong value types flagged:

```python
from django_device_bound_sessions.conf import DBSCConfig

DBSC: DBSCConfig = {"BOUND_COOKIE_AGE": 300, "ENFORCEMENT": "anonymous"}
```

## Settings

Set these in a `DBSC` dict in your settings:

| setting | default | |
|---|---|---|
| `BOUND_COOKIE_NAME` | `"dbsc_bound"` | |
| `BOUND_COOKIE_AGE` | `600` | seconds; this is how long a stolen bound cookie stays useful |
| `BOUND_COOKIE_GRACE` | `30` | extra seconds the server accepts after expiry |
| `BOUND_COOKIE_DOMAIN` / `_PATH` / `_SECURE` / `_HTTPONLY` / `_SAMESITE` | `None` / `"/"` / `True` / `True` / `"Lax"` | |
| `ALGORITHMS` | `["ES256", "RS256"]` | offered in preference order (`none` is never accepted) |
| `CHALLENGE_MAX_AGE` | `300` | seconds a challenge is valid |
| `CACHE_ALIAS` | `"default"` | cache that makes challenges single-use; use a shared cache in production |
| `SCOPE_ORIGIN` | `None` | `scope.origin` |
| `SCOPE_INCLUDE_SITE` | `False` | `scope.include_site` |
| `SCOPE_SPECIFICATION` | `[]` | e.g. `[{"type": "exclude", "domain": "*", "path": "/static"}]` |
| `ALLOWED_REFRESH_INITIATORS` | `[]` | |
| `REGISTRATION_PATH` / `REFRESH_PATH` | `None` | override the URLs (default: reversed from `django_device_bound_sessions.urls`) |
| `OFFER_ON_LOGIN` | `True` | |
| `OFFER_MAX_AGE` | `60` | seconds after `login()` that a registration offer can still be sent |
| `ENFORCEMENT` | `"anonymous"` | `"anonymous"`: treat the request as logged out. `"logout"`: flush the session. `"off"`: check `request.dbsc` yourself |

## Security notes

- **A binding is permanent for the life of the session.** The first device to register owns the
  session. Registration is refused (409) on a session that is already bound, so a stolen session
  cookie can't be used to move the session onto another device. To use a new device, log in again,
  which creates a new session.
- **The window before binding is unprotected, and it's kept short.** Until registration completes,
  whoever holds the session cookie could receive the registration offer. Offers are only sent for
  `OFFER_MAX_AGE` seconds after login and are used once. DBSC can't protect a session that was
  stolen before it was bound; like the spec, this library assumes the device wasn't compromised at
  login time.
- Challenges are signed with `SECRET_KEY` and expire. Each one is accepted once, enforced through
  the cache. Registration challenges are tied to the Django session that received them.
- A refresh with an invalid proof is rejected, but the DBSC session stays alive. Otherwise anyone
  holding a stolen cookie could knock the real device off.
- A refresh without the matching Django session (the user logged out, the session expired, or the
  binding was replaced) returns `{"continue": false}`, which tells the browser to stop. It never
  changes the session it was sent with.
- DBSC endpoints are CSRF-exempt, because the browser calls them without a token. The signed
  challenge authenticates them instead. Responses are `no-store` and `X-Frame-Options: DENY`.

## Testing your app

`django_device_bound_sessions.testing.DBSCBrowser` wraps a Django test `Client` and simulates the browser side of DBSC:

```python
from django_device_bound_sessions.testing import DBSCBrowser


def test_private_page(client, user):
    browser = DBSCBrowser(client)  # or algorithm="RS256"
    client.force_login(user)
    browser.get("/")  # registers automatically
    browser.expire_bound_cookie()
    assert browser.get("/private/").status_code == 200  # refreshes first, like Chrome
```

## Development

```bash
uv sync
uv run pre-commit install   # ruff lint + format and zizmor on every commit
uv run pytest
uv run mypy
uv run pyright
uv run ty check
```

CI (`.github/workflows/ci.yml`) runs on pushes to `main` and on pull requests:

- **Tests** on Python 3.12–3.15 with the latest Django 6.1.x, and Python 3.12–3.14 with the latest
  Django 5.2.x (LTS). There's also a run against the lowest versions allowed by `pyproject.toml`
  (Django 5.2.0, PyJWT 2.10.0).
- **Pre-commit** on every file: `ruff check` + `ruff format`, and [zizmor](https://docs.zizmor.sh/)
  for the workflows and Dependabot config. In CI, zizmor also runs its online audits, such as
  checking that each pinned action SHA is a real commit in that action's repository.
- **mypy** (strict, with django-stubs), **pyright** (strict on `src/` and `typecheck/`) and **ty**.

Actions are pinned to commit SHAs. Dependabot or Renovate can keep them up to date.

Run `uv run pre-commit run --all-files` to lint and format everything by hand. Ruff isn't a
project dependency. It runs only through pre-commit, so the hook's `rev` in
`.pre-commit-config.yaml` is the single ruff version used locally and in CI.

### Demo project

```bash
uv run example/manage.py migrate
uv run example/manage.py createsuperuser
uv run example/manage.py runserver
```

Open http://localhost:8000 in Chrome with DBSC enabled and log in. The home page shows the binding
status. The demo's bound cookie lives 60 seconds, and an **Expire bound cookie** button forces a
refresh, which you can watch in DevTools → Application → Device Bound Sessions.

DBSC requires HTTPS, except on `localhost`.

Protocol reference: <https://w3c.github.io/webappsec-dbsc/>
