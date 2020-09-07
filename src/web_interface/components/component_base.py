from types import MethodType
from typing import Any, Callable, List, NamedTuple

GET = 'GET'
POST = 'POST'


Route = NamedTuple('Route', [('rule', str), ('endpoint', str), ('methods', List[str])])


class AppRoute:
    def __init__(self, rule: str, endpoint: str, methods: List[str]):
        self.route = Route(rule, endpoint, methods)

    def __call__(self, view_function: Callable) -> Callable:
        if not hasattr(view_function, "view_routes"):
            view_function.view_routes = []
        view_function.view_routes.append(self.route)
        return view_function


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
                for route in method.view_routes:  # type: Route
                    self._app.add_url_rule(
                        rule=route.rule,
                        endpoint=route.endpoint,
                        view_func=method,
                        methods=route.methods
                    )


def _is_view_function(method: Any):
    return isinstance(method, MethodType) and hasattr(method, 'view_routes')
