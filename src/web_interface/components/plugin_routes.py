
import importlib
import inspect
import pkgutil

from flask_restx import Resource

from helperFunctions.fileSystem import get_src_dir
from web_interface.components.component_base import ComponentBase
from web_interface.rest.rest_resource_base import RestResourceBase

ROUTES_MODULE_NAME = 'routes'
PLUGIN_CATEGORIES = ['analysis', 'compare']
PLUGIN_DIR = f'{get_src_dir()}/plugins'


class PluginRoutes(ComponentBase):
    def _init_component(self):
        plugin_list = _find_plugins()
        self._register_all_plugin_endpoints(plugin_list)

    def _register_all_plugin_endpoints(self, plugins_by_category):
        for plugin_type, plugin_list in plugins_by_category:
            for plugin in plugin_list:
                if _module_has_routes(plugin, plugin_type):
                    self._import_module_routes(plugin, plugin_type)

    def _import_module_routes(self, plugin, plugin_type):
        module = importlib.import_module(f'plugins.{plugin_type}.{plugin}.{ROUTES_MODULE_NAME}.{ROUTES_MODULE_NAME}')
        if hasattr(module, 'PluginRoutes'):
            module.PluginRoutes(self._app, self._config, db=self.db, intercom=self.intercom)
        for rest_class in [
            element for element in [getattr(module, attribute) for attribute in dir(module)]
            if inspect.isclass(element) and issubclass(element, Resource) and element not in [Resource, RestResourceBase]
        ]:
            for endpoint, methods in rest_class.ENDPOINTS:
                self._api.add_resource(rest_class, endpoint, methods=methods, resource_class_kwargs={'config': self._config})


def _module_has_routes(plugin, plugin_type):
    plugin_components = _get_modules_in_path(f'{PLUGIN_DIR}/{plugin_type}/{plugin}')
    return ROUTES_MODULE_NAME in plugin_components


def _find_plugins():
    plugin_list = []
    for plugin_category in PLUGIN_CATEGORIES:
        plugin_list.append((plugin_category, _get_modules_in_path(f'{PLUGIN_DIR}/{plugin_category}')))
    return plugin_list


def _get_modules_in_path(path):
    return [module_name for _, module_name, _ in pkgutil.iter_modules([path])]
