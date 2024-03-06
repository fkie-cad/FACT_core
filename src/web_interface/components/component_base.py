from __future__ import annotations

from types import MethodType
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Callable

    from intercom.front_end_binding import InterComFrontEndBinding
    from storage.redis_status_interface import RedisStatusInterface
    from web_interface.frontend_database import FrontendDatabase

ROUTES_ATTRIBUTE = 'view_routes'

GET = 'GET'
POST = 'POST'


class Route(NamedTuple):
    rule: str
    methods: tuple[str, ...]


class AppRoute:
    """
    A Decorator for web interface view functions that imitates the functionality of Flask's ``app.route()`` .

    :Example:

        .. code-block:: python

           @AppRoute('/analysis/<uid>', 'GET', 'POST')
           def show_analysis(self, uid):

    :param rule: The endpoint route (e.g. "/about")
    :param methods: supported HTML Methods (e.g. ``'GET', 'POST'``)
    """

    def __init__(self, rule: str, *methods: str):
        self.route = Route(rule, methods)

    def __call__(self, view_function: Callable) -> Callable:
        if not hasattr(view_function, ROUTES_ATTRIBUTE):
            setattr(view_function, ROUTES_ATTRIBUTE, [])
        getattr(view_function, ROUTES_ATTRIBUTE).append(self.route)
        return view_function


class ComponentBase:
    def __init__(
        self,
        app,
        db: FrontendDatabase,
        intercom: InterComFrontEndBinding,
        status: RedisStatusInterface,
        api=None,
    ):
        self._app = app
        self._api = api
        self.db = db
        self.intercom = intercom
        self.status = status

        self._init_component()

    def _init_component(self):
        for attribute in dir(self):
            method = getattr(self, attribute)
            if _is_view_function(method):
                for route in getattr(method, ROUTES_ATTRIBUTE):  # type: Route
                    self._app.add_url_rule(rule=route.rule, view_func=method, methods=route.methods)


def _is_view_function(attribute: Any):
    return isinstance(attribute, MethodType) and hasattr(attribute, ROUTES_ATTRIBUTE)
