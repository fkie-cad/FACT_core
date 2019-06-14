from flask_restful import Resource

from helperFunctions.rest import success_message, error_message
from helperFunctions.web_interface import ConnectTo
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_statistic import StatisticDbViewer
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class RestStatus(Resource):
    URL = '/rest/status'

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

    @roles_accepted(*PRIVILEGES['status'])
    def get(self):
        components = ["frontend", "database", "backend"]
        status = {}
        with ConnectTo(StatisticDbViewer, self.config) as stats_db:
            for component in components:
                status[component] = stats_db.get_statistic(component)

        with ConnectTo(InterComFrontEndBinding, self.config) as sc:
            plugin_dict = sc.get_available_analysis_plugins()

        if not status:
            return error_message('Unknown Issue. Cannot Stat FACT.', self.URL, return_code=404)

        response = {
            'system_status': status,
            'plugins': plugin_dict,
        }
        return success_message(response, self.URL)
