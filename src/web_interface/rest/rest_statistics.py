from flask_restful import Resource

from helperFunctions.database import ConnectTo
from storage.db_interface_statistic import StatisticDbViewer

from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES
from web_interface.rest.helper import error_message


class RestStatistics(Resource):
    URL = '/rest/statistics'
    STATISTICS = ['general', 'firmware_meta', 'file_type', 'malware', 'crypto_material', 'unpacking', 'ips_and_uris',
                  'architecture', 'release_date', 'exploit_mitigations', 'known_vulnerabilities', 'software_components',
                  'elf_executable']

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

    @roles_accepted(*PRIVILEGES['status'])
    def get(self, stat_name=None):
        if not stat_name:
            return self._get_all_stats_from_db()
        return self._get_certain_stats_from_db(stat_name)

    def _get_all_stats_from_db(self):
        with ConnectTo(StatisticDbViewer, self.config) as stats_db:
            statistics_dict = {}
            for stat in self.STATISTICS:
                statistics_dict[stat] = stats_db.get_statistic(stat)

            self._delete_id_and_check_empty_stat(statistics_dict)

        return statistics_dict

    def _get_certain_stats_from_db(self, statistic_name):
        with ConnectTo(StatisticDbViewer, self.config) as stats_db:
            statistic_dict = {statistic_name: stats_db.get_statistic(statistic_name)}
            self._delete_id_and_check_empty_stat(statistic_dict)
        if statistic_name not in self.STATISTICS:
            return error_message('A statistic with the ID {} does not exist'.format(statistic_name), self.URL, dict(stat_name=statistic_name))

        return statistic_dict

    @staticmethod
    def _delete_id_and_check_empty_stat(stats_dict):
        for stat in stats_dict.copy():
            if stats_dict[stat] is not None:
                del stats_dict[stat]['_id']
            if stats_dict[stat] is None:
                stats_dict[stat] = {}
