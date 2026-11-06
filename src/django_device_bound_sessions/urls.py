from django.urls import URLPattern, path

from . import views

app_name = "django_device_bound_sessions"

urlpatterns: list[URLPattern] = [
    path("register/", views.register, name="register"),
    path("refresh/", views.refresh, name="refresh"),
]
