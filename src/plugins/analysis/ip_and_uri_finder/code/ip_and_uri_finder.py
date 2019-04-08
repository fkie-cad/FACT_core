import logging
import os

import geoip2.database
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder, ip_and_uri_finder_analysis
from common_helper_files import get_dir_of_file
from geoip2.errors import AddressNotFoundError
from maxminddb.errors import InvalidDatabaseError

from analysis.PluginBase import AnalysisBasePlugin

DATABASE_PATH = os.path.join(get_dir_of_file(__file__), '../bin/GeoLite2-City/GeoLite2-City.mmdb')


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This plug-in finds IPs and URIs
    '''
    NAME = 'ip_and_uri_finder'
    DEPENDENCIES = []
    MIME_BLACKLIST = ['filesystem']
    DESCRIPTION = 'search for IPs and URIs'
    VERSION = ip_and_uri_finder_analysis.system_version

    def __init__(self, config=None):

        self.config = config

        # additional init stuff can go here
        self.finder_module = CommonAnalysisIPAndURIFinder()

        self.reader = geoip2.database.Reader(DATABASE_PATH)

        super().__init__(config=config, plugin_path=__file__)

    def process_object(self, file_object):
        result = self.finder_module.analyze_file(file_object.file_path, separate_ipv6=True)
        logging.debug(result)
        for key in ['uris', 'ips_v4', 'ips_v6']:
            result[key] = self._remove_duplicates(result[key])
        result = self.add_geo_uri_to_ip(result)
        file_object.processed_analysis[self.NAME] = result
        file_object.processed_analysis[self.NAME]['summary'] = self._get_summary(result)
        return file_object

    def add_geo_uri_to_ip(self, result):
        for key in ['ips_v4', 'ips_v6']:
            result[key] = self.link_ips_with_geo_location(result[key])
        return result

    def find_geo_location(self, ip_address):
        response = self.reader.city(ip_address)
        return '{}, {}'.format(response.location.latitude, response.location.longitude)

    def link_ips_with_geo_location(self, ip_adresses):
        linked_ip_geo_list = []
        for ip in ip_adresses:
            try:
                ip_tuple = ip, self.find_geo_location(ip)
            except (AddressNotFoundError, FileNotFoundError, ValueError, InvalidDatabaseError) as exception:
                logging.debug('{} {}'.format(type(exception), str(exception)))
                ip_tuple = ip, ''
            linked_ip_geo_list.append(ip_tuple)
        return linked_ip_geo_list

    @staticmethod
    def _get_summary(results):
        summary = []
        for key in ['uris']:
            summary.extend(results[key])
        for key in ['ips_v4', 'ips_v6']:
            for i in results[key]:
                summary.append(i[0])
        return summary

    @staticmethod
    def _remove_duplicates(list_):
        return list(set(list_))
