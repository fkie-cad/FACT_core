from web_interface.components.component_base import ComponentBase


class PluginRoutes(ComponentBase):

    def _init_component(self):
        self._app.add_url_rule('/plugins/dummy', 'plugins/dummy', self._get_dummy)

    @staticmethod
    def _get_dummy():
        return 'dummy'
