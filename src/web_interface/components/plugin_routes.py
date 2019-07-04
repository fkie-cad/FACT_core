
import importlib
import inspect
import pkgutil

from flask_restful import Resource
from helperFunctions.fileSystem import get_src_dir
from web_interface.components.component_base import ComponentBase

ROUTES_MODULE_NAME = 'routes'
PLUGIN_CATEGORIES = ['analysis', 'compare']
PLUGIN_DIR = '{}/plugins'.format(get_src_dir())


class PluginRoutes(ComponentBase):
    def _init_component(self):
        plugin_list = self._find_plugins()
        self._register_all_plugin_endpoints(plugin_list)

    def _register_all_plugin_endpoints(self, plugins_by_category):
        for plugin_type, plugin_list in plugins_by_category:
            for plugin in plugin_list:
                if self._module_has_routes(plugin, plugin_type):
                    self._import_module_routes(plugin, plugin_type)

    def _find_plugins(self):
        plugin_list = []
        for plugin_category in PLUGIN_CATEGORIES:
            plugin_list.append((plugin_category, self._get_modules_in_path('{}/{}'.format(PLUGIN_DIR, plugin_category))))
        return plugin_list

    def _module_has_routes(self, plugin, plugin_type):
        plugin_components = self._get_modules_in_path('{}/{}/{}'.format(PLUGIN_DIR, plugin_type, plugin))
        return ROUTES_MODULE_NAME in plugin_components

    def _import_module_routes(self, plugin, plugin_type):
        module = importlib.import_module('plugins.{0}.{1}.{2}.{2}'.format(plugin_type, plugin, ROUTES_MODULE_NAME))
        if hasattr(module, 'PluginRoutes'):
            module.PluginRoutes(self._app, self._config)
        for rest_class in [
            element for element in [getattr(module, attribute) for attribute in dir(module)]
            if inspect.isclass(element) and issubclass(element, Resource) and not element == Resource
        ]:
            for endpoint, methods in rest_class.ENDPOINTS:
                self._api.add_resource(rest_class, endpoint, methods=methods, resource_class_kwargs={'config': self._config})

    @staticmethod
    def _get_modules_in_path(path):
        return [module_name for _, module_name, _ in pkgutil.iter_modules([path])]
