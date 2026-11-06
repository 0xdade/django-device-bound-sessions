from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponseRedirect, JsonResponse
from django.urls import URLPattern, URLResolver, include, path

from django_device_bound_sessions.api import DBSCHttpRequest
from django_device_bound_sessions.decorators import dbsc_exempt


def whoami(request: DBSCHttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "user": request.user.get_username() if request.user.is_authenticated else None,
            "dbsc_session": request.dbsc.session_id,
            "bound": request.dbsc.bound,
        }
    )


async def async_whoami(request: DBSCHttpRequest) -> JsonResponse:
    """Async views get the user via request.auser(); enforcement must cover it."""
    user = await request.auser()
    return JsonResponse(
        {
            "user": user.get_username() if user.is_authenticated else None,
            "bound": request.dbsc.bound,
        }
    )


@dbsc_exempt
def exempt_whoami(request: DBSCHttpRequest) -> JsonResponse:
    return whoami(request)


def redirect_home(request: HttpRequest) -> HttpResponseRedirect:
    return HttpResponseRedirect("/")


def logout_view(request: HttpRequest) -> JsonResponse:
    logout(request)
    return JsonResponse({"ok": True})


urlpatterns: list[URLPattern | URLResolver] = [
    path("", whoami),
    path("async/", async_whoami),
    path("exempt/", exempt_whoami),
    path("redirect/", redirect_home),
    path("logout/", logout_view),
    path("dbsc/", include("django_device_bound_sessions.urls")),
]
