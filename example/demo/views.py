"""Demo views.

``home`` is typed with ``DBSCHttpRequest``, so it reads ``request.dbsc``
directly. ``status`` is typed against a plain ``HttpRequest``, like most
existing Django code, so it uses ``get_dbsc_state()``. Both type-check.
"""

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods

from django_device_bound_sessions.api import DBSCHttpRequest, get_dbsc_state
from django_device_bound_sessions.cookies import delete_bound_cookie


def home(request: DBSCHttpRequest) -> HttpResponse:
    return render(request, "home.html", {"binding": request.dbsc.binding})


def status(request: HttpRequest) -> JsonResponse:
    """The DBSC state as JSON, for a view typed against plain HttpRequest."""
    state = get_dbsc_state(request)
    binding = state.binding
    return JsonResponse(
        {
            "user": request.user.get_username() if request.user.is_authenticated else None,
            "registered": state.registered,
            "bound": state.bound,
            "binding": None
            if binding is None
            else {
                "session_id": binding.session_id,
                "algorithm": binding.algorithm,
                "thumbprint": binding.thumbprint,
                "created_at": binding.created_at.isoformat(),
                "last_refreshed_at": (
                    binding.last_refreshed_at.isoformat() if binding.last_refreshed_at else None
                ),
            },
        }
    )


@require_http_methods(["POST"])  # same as @require_POST; types under ty too
def expire_bound_cookie(request: HttpRequest) -> HttpResponseRedirect:
    """Drop the bound cookie so Chrome has to refresh it with its key."""
    response = redirect("home")
    delete_bound_cookie(response)
    return response
