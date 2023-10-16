import os
from itertools import chain

from flask import Flask
from flask_restx import Api

from helperFunctions.fileSystem import get_src_dir
from web_interface.components.plugin_routes import (
    PLUGIN_CATEGORIES,
    PluginRoutes,
    _find_plugins,
    _get_modules_in_path,
    _module_has_routes,
)


class PluginRoutesMock(PluginRoutes):
    def __init__(self, app, db=None, intercom=None, api=None, status=None):  # noqa: PLR0913
        self._app = app
        self._api = api
        self.db = db
        self.intercom = intercom
        self.status = status


class TestPluginRoutes:
    def setup_method(self):
        self.app = Flask(__name__)
        self.app.config.from_object(__name__)
        self.api = Api(self.app)

    def test_get_modules_in_path(self):
        plugin_dir_path = os.path.join(get_src_dir(), 'plugins')  # noqa: PTH118
        plugin_folder_modules = _get_modules_in_path(plugin_dir_path)
        assert len(plugin_folder_modules) >= 3  # noqa: PLR2004
        for category in PLUGIN_CATEGORIES:
            assert category in plugin_folder_modules

    def test_find_plugins(self):
        result = _find_plugins()
        categories, plugins = zip(*result)
        plugins = chain(*plugins)
        assert all(c in categories for c in PLUGIN_CATEGORIES)
        assert 'dummy' in plugins
        assert 'file_coverage' in plugins

    def test_module_has_routes(self):
        assert _module_has_routes('dummy', 'analysis') is True
        assert _module_has_routes('file_type', 'analysis') is False

    def test_import_module_routes(self):
        dummy_endpoint = 'plugins/dummy'
        plugin_routes = PluginRoutesMock(self.app, api=self.api)

        assert dummy_endpoint not in self._get_app_endpoints(self.app)

        plugin_routes._import_module_routes('dummy', 'analysis')
        assert dummy_endpoint in self._get_app_endpoints(self.app)

        test_client = self.app.test_client()
        result = test_client.get(dummy_endpoint)
        assert result.data == b'dummy'

    def test_import_module_routes__rest(self):
        dummy_endpoint = 'plugins/dummy/rest'
        plugin_routes = PluginRoutesMock(self.app, api=self.api)

        assert dummy_endpoint not in self._get_app_endpoints(self.app)

        plugin_routes._import_module_routes('dummy', 'analysis')

        test_client = self.app.test_client()
        result = test_client.get(dummy_endpoint).json
        assert 'dummy' in result
        assert 'rest' in result['dummy']

    @staticmethod
    def _get_app_endpoints(app):
        rules = []
        for rule in app.url_map.iter_rules():
            rules.append(rule.endpoint)
        return rules
