from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import URLPattern, URLResolver, include, path

from . import views

urlpatterns: list[URLPattern | URLResolver] = [
    path("", views.home, name="home"),
    path("status/", views.status, name="status"),
    path("expire/", views.expire_bound_cookie, name="expire"),
    path("login/", auth_views.LoginView.as_view(), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("admin/", admin.site.urls),
    path("dbsc/", include("django_device_bound_sessions.urls")),
]
