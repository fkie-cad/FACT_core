from types import MethodType
from typing import Any, Callable, List, NamedTuple

GET = 'GET'
POST = 'POST'


Route = NamedTuple('Route', [('rule', str), ('endpoint', str), ('methods', List[str])])


class AddRouteDecorator:
    def __init__(self, route: Route):
        self.route = route

    def __call__(self, view_function: Callable) -> Callable:
        if not hasattr(view_function, "routes"):
            view_function.routes = []
        view_function.routes.append(self.route)
        return view_function


def add_route(rule: str, endpoint: str, methods: List[str]):
    return AddRouteDecorator(Route(rule, endpoint, methods))


class ComponentBase:
    def __init__(self, app, config, api=None):
        self._app = app
        self._config = config
        self._api = api

        self._init_component()

    def _init_component(self):
        for attribute in dir(self):
            method = getattr(self, attribute)
            if _is_view_function(method):
                for route in method.routes:  # type: Route
                    self._app.add_url_rule(
                        rule=route.rule,
                        endpoint=route.endpoint,
                        view_func=method,
                        methods=route.methods
                    )


def _is_view_function(method: Any):
    return isinstance(method, MethodType) and hasattr(method, 'routes')
