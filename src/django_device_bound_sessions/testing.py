"""A simulated DBSC-capable browser for tests.

Wraps a ``django.test.Client`` and plays the browser's side of the protocol:
it watches for ``Secure-Session-Registration``, registers a fresh key pair,
and refreshes the bound cookie (including the 403 challenge round trip)
before requests when the cookie is missing::

    browser = DBSCBrowser(client)
    client.force_login(user)
    browser.get("/")            # receives the registration offer, registers
    browser.expire_bound_cookie()
    browser.get("/private/")    # refreshes first, like Chrome would
"""

from typing import TYPE_CHECKING, Any, Literal

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.test import Client
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from . import sf
from .api import CHALLENGE_HEADER, REGISTRATION_HEADER, RESPONSE_HEADER, SESSION_ID_HEADER
from .proof import JWK

if TYPE_CHECKING:
    # django-stubs' name for what the test client returns; not public API.
    from django.test.client import (
        _MonkeyPatchedWSGIResponse as TestResponse,  # pyright: ignore[reportPrivateUsage]
    )

type PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
type Algorithm = Literal["ES256", "RS256"]


class DBSCBrowser:
    def __init__(
        self,
        client: Client,
        algorithm: Algorithm = "ES256",
        auto_register: bool = True,
        auto_refresh: bool = True,
    ) -> None:
        self.client = client
        self.algorithm: Algorithm = algorithm
        self.auto_register = auto_register
        self.auto_refresh = auto_refresh
        self.private_key: PrivateKey
        if algorithm == "ES256":
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        elif algorithm == "RS256":
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise ValueError(f"Unsupported algorithm {algorithm!r}")
        #: ``(path, challenge)`` from the last registration offer, until used.
        self.pending_registration: tuple[str, str | None] | None = None
        #: The last session config received from the server.
        self.config: dict[str, Any] | None = None
        #: The cached refresh challenge.
        self.challenge: str | None = None
        #: Every response from the most recent :meth:`refresh`.
        self.last_refresh_responses: list[TestResponse] = []

    # -- keys / proofs ----------------------------------------------------

    @property
    def public_jwk(self) -> JWK:
        public_key = self.private_key.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return ECAlgorithm.to_jwk(public_key, as_dict=True)
        return RSAAlgorithm.to_jwk(public_key, as_dict=True)

    def make_proof(
        self,
        jti: str | None,
        include_jwk: bool = False,
        key: PrivateKey | None = None,
        **extra_claims: Any,
    ) -> str:
        headers: dict[str, Any] = {"typ": "dbsc+jwt"}
        if include_jwk:
            headers["jwk"] = self.public_jwk
        return jwt.encode(
            {"jti": jti, **extra_claims},
            key or self.private_key,
            algorithm=self.algorithm,
            headers=headers,
        )

    # -- state ------------------------------------------------------------

    @property
    def session_config(self) -> dict[str, Any]:
        """The current session config. Raises if the browser isn't registered."""
        if self.config is None:
            raise RuntimeError("Not registered: no session config")
        return self.config

    @property
    def session_id(self) -> str | None:
        return self.config["session_identifier"] if self.config else None

    @property
    def bound_cookie_name(self) -> str | None:
        return self.config["credentials"][0]["name"] if self.config else None

    def has_bound_cookie(self) -> bool:
        name = self.bound_cookie_name
        morsel = self.client.cookies.get(name) if name else None
        return bool(morsel and morsel.value and morsel["max-age"] not in (0, "0"))

    def expire_bound_cookie(self) -> None:
        if self.bound_cookie_name:
            self.client.cookies.pop(self.bound_cookie_name, None)

    # -- protocol ---------------------------------------------------------

    def observe(self, response: "TestResponse") -> "TestResponse":
        """Process DBSC headers on a response, as a browser would."""
        if REGISTRATION_HEADER in response.headers:
            for item, params in sf.parse_list(response.headers[REGISTRATION_HEADER]):
                algs = [v for v, _ in item] if isinstance(item, list) else []
                path, challenge = params.get("path"), params.get("challenge")
                if self.algorithm in algs and isinstance(path, str):
                    self.pending_registration = (
                        path,
                        challenge if isinstance(challenge, str) else None,
                    )
                    break
        if CHALLENGE_HEADER in response.headers:
            for value, params in sf.parse_list(response.headers[CHALLENGE_HEADER]):
                if not isinstance(value, str):
                    continue
                if self.session_id is None or params.get("id") == self.session_id:
                    self.challenge = value
        return response

    def register(self) -> "TestResponse":
        if self.pending_registration is None:
            raise RuntimeError("No pending registration offer")
        path, challenge = self.pending_registration
        self.pending_registration = None
        proof = self.make_proof(challenge, include_jwk=True)
        response = self.client.post(path, headers={RESPONSE_HEADER: sf.serialize_string(proof)})
        if response.status_code == 200:
            self.config = response.json()
            self.challenge = None
            self.observe(response)
        return response

    def refresh(self, max_attempts: int = 3) -> "TestResponse":
        """Run the refresh flow. Returns the final response."""
        if self.config is None or self.session_id is None:
            raise RuntimeError("Not registered")
        session_id = self.session_id
        refresh_url: str = self.config["refresh_url"]
        self.last_refresh_responses = []
        for _ in range(max_attempts):
            headers = {SESSION_ID_HEADER: sf.serialize_string(session_id)}
            if self.challenge:
                headers[RESPONSE_HEADER] = sf.serialize_string(self.make_proof(self.challenge))
                self.challenge = None
            response = self.observe(self.client.post(refresh_url, headers=headers))
            self.last_refresh_responses.append(response)
            if not (response.status_code == 403 and self.challenge):
                break
        response = self.last_refresh_responses[-1]
        if response.status_code == 200:
            body: dict[str, Any] = response.json() if response.content else {}
            if body.get("continue") is False:
                self.config = None
            elif body:
                self.config = body
        elif 400 <= response.status_code < 500 and response.status_code not in (403, 407, 429):
            self.config = None  # the browser terminates the session
        return response

    # -- requests ---------------------------------------------------------

    def request(self, method: Literal["get", "post"], path: str, **kwargs: Any) -> "TestResponse":
        if self.auto_refresh and self.config and not self.has_bound_cookie():
            self.refresh()
        send = self.client.get if method == "get" else self.client.post
        response = self.observe(send(path, **kwargs))
        if self.auto_register and self.pending_registration:
            self.register()
        return response

    def get(self, path: str, **kwargs: Any) -> "TestResponse":
        return self.request("get", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> "TestResponse":
        return self.request("post", path, **kwargs)
