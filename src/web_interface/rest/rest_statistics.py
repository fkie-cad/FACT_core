from flask_restful import Resource

from helperFunctions.database import ConnectTo
from storage.db_interface_statistic import StatisticDbViewer

from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES
from web_interface.rest.helper import error_message


class RestStatistics(Resource):
    URL = '/rest/statistics'

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

    @roles_accepted(*PRIVILEGES['status'])
    def get(self, stat_name=None):
        if not stat_name:
            return self._get_all_stats_from_db()
        return self._get_certain_stats_from_db(stat_name)

    def _get_all_stats_from_db(self):
        with ConnectTo(StatisticDbViewer, self.config) as stats_db:
            statistics_dict = {
                'general': stats_db.get_statistic('general'),
                'firmware_meta': stats_db.get_statistic('firmware_meta'),
                'file_type': stats_db.get_statistic('file_type'),
                'malware': stats_db.get_statistic('malware'),
                'crypto_material': stats_db.get_statistic('crypto_material'),
                'unpacking': stats_db.get_statistic('unpacking'),
                'ips_and_uris': stats_db.get_statistic('ips_and_uris'),
                'architecture': stats_db.get_statistic('architecture'),
                'release_date': stats_db.get_statistic('release_date'),
                'exploit_mitigations': stats_db.get_statistic('exploit_mitigations'),
                'known_vulnerabilities': stats_db.get_statistic('known_vulnerabilities'),
                'software_components': stats_db.get_statistic('software_components'),
                'elf_executable': stats_db.get_statistic('elf_executable'),
            }
            self._delete_id_and_empty_stats(statistics_dict)

        return statistics_dict

    def _get_certain_stats_from_db(self, statistic_name):
        with ConnectTo(StatisticDbViewer, self.config) as stats_db:
            statistic_dict = {statistic_name: stats_db.get_statistic(statistic_name)}
            self._delete_id_and_empty_stats(statistic_dict)
        if not statistic_dict:
            return error_message('No statistic with the ID {} found'.format(statistic_name), self.URL, dict(stat_name=statistic_name))

        return statistic_dict

    @staticmethod
    def _delete_id_and_empty_stats(stats_dict):
        for stat in stats_dict.copy():
            if stats_dict[stat] is not None:
                del stats_dict[stat]['_id']
            elif stats_dict[stat] is None:
                del stats_dict[stat]
