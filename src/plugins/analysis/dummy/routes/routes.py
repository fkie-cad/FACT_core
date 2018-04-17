from flask_restful import Resource

from helperFunctions.rest import success_message
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class PluginRoutes(ComponentBase):

    def _init_component(self):
        self._app.add_url_rule('/plugins/dummy', 'plugins/dummy', self._get_dummy)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _get_dummy(self):
        return 'dummy', 200


class DummyRoutesRest(Resource):
    ENDPOINTS = [('/plugins/dummy/rest', ['GET'])]

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def get(self):
        return success_message({'dummy': 'rest'}, self.ENDPOINTS[0][0])
