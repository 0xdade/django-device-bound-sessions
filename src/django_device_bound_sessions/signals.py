from typing import Any

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.http import HttpRequest

from .api import offer_registration
from .conf import dbsc_settings


@receiver(user_logged_in, dispatch_uid="django_device_bound_sessions.offer_on_login")
def _offer_on_login(
    sender: type[AbstractBaseUser],
    request: HttpRequest | None,
    user: AbstractBaseUser,
    **kwargs: Any,
) -> None:
    if request is not None and dbsc_settings.OFFER_ON_LOGIN:
        offer_registration(request)
