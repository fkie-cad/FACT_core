from enum import Enum
from typing import Callable, List, NamedTuple


class RequestMethod(Enum):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'


Route = NamedTuple('Route', [('rule', str), ('endpoint', str), ('methods', List[str])])


class AddRouteDecorator:
    def __init__(self, rule: str, endpoint: str, method: RequestMethod):
        self.rule = rule
        self.endpoint = endpoint
        self.method = method

    def __call__(self, view_function: Callable) -> Callable:
        if not hasattr(view_function, "routes"):
            view_function.routes = []
        view_function.routes.append(Route(self.rule, self.endpoint, [self.method.value]))
        return view_function


def add_route(rule: str, endpoint: str, method: RequestMethod):
    return AddRouteDecorator(rule, endpoint, method)


class ComponentBase:
    def __init__(self, app, config, api=None):
        self._app = app
        self._config = config
        self._api = api

        self._init_component()

    def _init_component(self):
        for attr_name in dir(self):
            method = getattr(self, attr_name)
            if hasattr(method, 'routes'):
                route_list: List[Route] = method.routes
                for route in route_list:
                    self._app.add_url_rule(
                        rule=route.rule,
                        endpoint=route.endpoint,
                        view_func=method,
                        methods=route.methods
                    )
