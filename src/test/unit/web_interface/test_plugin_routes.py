from flask import Flask
import os
from unittest import TestCase

from helperFunctions.config import get_config_for_testing
from helperFunctions.fileSystem import get_src_dir

from web_interface.components.plugin_routes import PluginRoutes, PLUGIN_CATEGORIES


class PluginRoutesMock(PluginRoutes):
    def __init__(self, app, config):
        self._app = app
        self._config = config


class TestPluginRoutes(TestCase):

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.from_object(__name__)
        self.config = get_config_for_testing()

    def test__get_modules_in_path(self):
        plugin_dir_path = os.path.join(get_src_dir(), 'plugins')
        plugin_folder_modules = PluginRoutes._get_modules_in_path(plugin_dir_path)
        assert len(plugin_folder_modules) >= 3
        for category in PLUGIN_CATEGORIES:
            assert category in plugin_folder_modules

    def test__module_has_routes(self):
        plugin_routes = PluginRoutes(self.app, self.config)
        assert plugin_routes._module_has_routes('dummy', 'analysis') is True
        assert plugin_routes._module_has_routes('file_type', 'analysis') is False

    def test__import_module_routes(self):
        dummy_endpoint = 'plugins/dummy'
        plugin_routes = PluginRoutesMock(self.app, self.config)

        assert dummy_endpoint not in self._get_app_endpoints(self.app)

        plugin_routes._import_module_routes('dummy', 'analysis')
        assert dummy_endpoint in self._get_app_endpoints(self.app)

        test_client = self.app.test_client()
        rv = test_client.get('/plugins/dummy')
        assert rv.data == b'dummy'

    @staticmethod
    def _get_app_endpoints(app):
        rules = []
        for rule in app.url_map.iter_rules():
            rules.append(rule.endpoint)
        return rules
