from flask_restx import Namespace

from fact.helperFunctions.database import get_shared_session
from fact.web_interface.rest.helper import error_message
from fact.web_interface.rest.rest_resource_base import RestResourceBase
from fact.web_interface.security.decorator import roles_accepted
from fact.web_interface.security.privileges import PRIVILEGES

STATISTICS = [
    'architecture',
    'crypto_material',
    'elf_executable',
    'exploit_mitigations',
    'file_type',
    'firmware_meta',
    'general',
    'ips_and_uris',
    'known_vulnerabilities',
    'release_date',
    'software_components',
    'unpacking',
]

api = Namespace('rest/statistics', description='Query all FACT statistics or a certain one')


def _delete_id_and_check_empty_stat(stats_dict):
    for stat in stats_dict.copy():
        if stats_dict[stat] is not None:
            del stats_dict[stat]['_id']
        if stats_dict[stat] is None:
            stats_dict[stat] = {}


@api.route('', doc={'description': 'Retrieves all statistics from the FACT database as raw JSON data.'})
class RestStatisticsWithoutName(RestResourceBase):
    URL = '/rest/statistics'

    @roles_accepted(*PRIVILEGES['status'])
    @api.doc(responses={200: 'Success', 400: 'Unknown stats category'})
    def get(self):
        """
        Get all statistics
        """
        statistics_dict = {}

        with get_shared_session(self.db.stats_viewer) as stats_db:
            for stat in STATISTICS:
                statistics_dict[stat] = stats_db.get_statistic(stat)

        _delete_id_and_check_empty_stat(statistics_dict)

        return statistics_dict


@api.route(
    '/<string:stat_name>',
    doc={'description': 'Retrieves statistics for a specific category', 'params': {'stat_name': "Statistic's name"}},
)
class RestStatisticsWithName(RestResourceBase):
    URL = '/rest/statistics'

    @roles_accepted(*PRIVILEGES['status'])
    @api.doc(responses={200: 'Success', 400: 'Unknown stats category'})
    def get(self, stat_name):
        """
        Get specific statistic
        """
        statistic_dict = {stat_name: self.db.stats_viewer.get_statistic(stat_name)}
        _delete_id_and_check_empty_stat(statistic_dict)
        if stat_name not in STATISTICS:
            return error_message(
                f'A statistic with the ID {stat_name} does not exist', self.URL, {'stat_name': stat_name}
            )

        return statistic_dict
