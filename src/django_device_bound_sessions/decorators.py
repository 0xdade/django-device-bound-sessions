from collections.abc import Callable
from functools import wraps


def dbsc_exempt[**P, R](view_func: Callable[P, R]) -> Callable[P, R]:
    """Skip DBSC enforcement and registration offers for this view."""

    @wraps(view_func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        return view_func(*args, **kwargs)

    setattr(wrapper, "dbsc_exempt", True)  # noqa: B010 - not a declared attribute
    return wrapper
