import logging
import secrets
from collections.abc import Callable

from django.contrib.auth import SESSION_KEY as AUTH_SESSION_KEY
from django.http import HttpRequest, HttpResponse, HttpResponseBase, JsonResponse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.clickjacking import xframe_options_deny
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .api import (
    CHALLENGE_HEADER,
    RESPONSE_HEADER,
    SESSION_ID_HEADER,
    DeviceBinding,
    build_session_config,
    challenge_header_value,
)
from .challenges import (
    ChallengeError,
    StaleChallenge,
    check_refresh_challenge,
    check_registration_challenge,
)
from .conf import dbsc_settings
from .cookies import delete_bound_cookie, set_bound_cookie
from .decorators import dbsc_exempt
from .proof import (
    ProofError,
    jwk_thumbprint,
    parse_proof_header,
    verify_refresh_proof,
    verify_registration_proof,
)
from .structured_fields import StructuredFieldError, parse_string_item

logger = logging.getLogger("django_device_bound_sessions")


View = Callable[[HttpRequest], HttpResponseBase]


def _endpoint(view: View) -> View:
    # The browser calls these directly, without a CSRF token; the signed
    # challenge in the proof is what authenticates the request.
    # require_http_methods(["POST"]) is exactly require_POST, but django-stubs
    # types it as a generic function, which every type checker (incl. ty) can solve.
    post_only = require_http_methods(["POST"])
    return csrf_exempt(post_only(never_cache(xframe_options_deny(dbsc_exempt(view)))))


def _error(status: int, message: str) -> HttpResponse:
    logger.info("DBSC request rejected: %s", message)
    return HttpResponse(message, status=status, content_type="text/plain")


def _terminate_response() -> JsonResponse:
    response = JsonResponse({"continue": False})
    delete_bound_cookie(response)
    return response


def _challenge(session_id: str) -> HttpResponse:
    response = HttpResponse(status=403)
    response.headers[CHALLENGE_HEADER] = challenge_header_value(session_id)
    return response


@_endpoint
def register(request: HttpRequest) -> HttpResponseBase:
    """Registration endpoint: the browser POSTs a proof carrying its new key."""
    if AUTH_SESSION_KEY not in request.session:
        return _error(401, "Not logged in")
    if DeviceBinding.from_session(request.session) is not None:
        # A session is bound to the device that registered it, for good.
        # Rebinding would let anyone holding the session cookie move the
        # session to their own device; binding a new device means a new login.
        return _error(409, "Session is already bound to a device")

    try:
        token = parse_proof_header(request.headers.get(RESPONSE_HEADER))
        proof = verify_registration_proof(token, dbsc_settings.ALGORITHMS)
        check_registration_challenge(request.session, proof.claims["jti"])
    except (ProofError, ChallengeError) as exc:
        return _error(400, str(exc))

    binding = DeviceBinding(
        session_id=secrets.token_urlsafe(32),
        algorithm=proof.algorithm,
        public_key=proof.jwk,
        thumbprint=jwk_thumbprint(proof.jwk),
        user_agent=request.headers.get("User-Agent", "")[:512],
        created_at=timezone.now(),
    )
    binding.save(request.session)

    response = JsonResponse(build_session_config(binding.session_id))
    set_bound_cookie(response, binding.session_id)
    # Pre-seed a challenge so the first refresh needs no extra round trip.
    response.headers[CHALLENGE_HEADER] = challenge_header_value(binding.session_id)
    return response


@_endpoint
def refresh(request: HttpRequest) -> HttpResponseBase:
    """Refresh endpoint: exchange proof of key possession for a bound cookie."""
    try:
        session_id = parse_string_item(request.headers.get(SESSION_ID_HEADER, ""))
    except StructuredFieldError:
        return _error(400, "Missing or malformed Sec-Secure-Session-Id")

    # The binding lives in the Django session, so the long-lived session
    # cookie must accompany the refresh. If it's gone, expired, logged out,
    # or bound to a different key, tell the browser to stop refreshing.
    binding = DeviceBinding.from_session(request.session)
    if (
        binding is None
        or binding.session_id != session_id
        or AUTH_SESSION_KEY not in request.session
    ):
        return _terminate_response()

    header = request.headers.get(RESPONSE_HEADER)
    if not header:
        return _challenge(session_id)

    try:
        token = parse_proof_header(header)
        proof = verify_refresh_proof(token, binding.algorithm, binding.public_key)
        check_refresh_challenge(session_id, proof.claims["jti"])
    except StaleChallenge:
        return _challenge(session_id)
    except (ProofError, ChallengeError) as exc:
        # Not proof of this key: reject without unbinding, so a stolen
        # cookie can't be used to kill the legitimate device's session.
        return _error(400, str(exc))

    binding.refreshed(timezone.now()).save(request.session)

    response = JsonResponse(build_session_config(session_id))
    set_bound_cookie(response, session_id)
    response.headers[CHALLENGE_HEADER] = challenge_header_value(session_id)
    return response
