from flask_restx import Namespace

from web_interface.rest.helper import error_message, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

api = Namespace('rest/status', description="Request FACT's system status")


@api.route('')
class RestStatus(RestResourceBase):
    URL = '/rest/status'

    @roles_accepted(*PRIVILEGES['status'])
    @api.doc(responses={200: 'Success', 400: 'Error'})
    def get(self):
        """
        Request system status
        Request a json document showing the system state of FACT, similar to the system health page of the GUI
        """
        components = ['frontend', 'database', 'backend']
        status = {}
        for component in components:
            status[component] = self.db.stats_viewer.get_statistic(component)

        plugins = self.intercom.get_available_analysis_plugins()

        if not any(value is not None for value in status.values()):
            return error_message('Cannot get FACT component status: Intercom may be down', self.URL, return_code=404)

        response = {
            'system_status': status,
            'plugins': self._condense_plugin_information(plugins),
        }

        if status['backend'] is not None and 'analysis' in status['backend']:
            analysis_status = self.status.get_analysis_status()
            status['backend']['analysis'].update(analysis_status)
        return success_message(response, self.URL)

    @staticmethod
    def _condense_plugin_information(plugins):
        plugins.pop('unpacker', None)

        for name, information in plugins.items():
            description, _, _, version, _, _, _, _ = information
            plugins[name] = {'description': description, 'version': version}

        return plugins
