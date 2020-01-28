import logging
from contextlib import suppress
from itertools import product
from pathlib import Path
from re import search

import geoip2.database
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder, ip_and_uri_finder_analysis
from geoip2.errors import AddressNotFoundError
from maxminddb.errors import InvalidDatabaseError

from analysis.PluginBase import AnalysisBasePlugin

GEOIP_DATABASE_PATH = Path(__file__).parent.parent / 'bin/GeoLite2-City/GeoLite2-City.mmdb'

IP_V4_BLACKLIST = [
    r'127.0.[0-9]+.1',  # localhost
    r'255.[0-9]+.[0-9]+.[0-9]+'  # subnetmasks
]
IP_V6_BLACKLIST = [  # trivial adresses
    r'^[0-9A-Za-z]::$',
    r'^::[0-9A-Za-z]$',
    r'^[0-9A-Za-z]::[0-9A-Za-z]$',
    r'^::$'
]


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This plug-in finds IPs and URIs
    '''
    NAME = 'ip_and_uri_finder'
    DEPENDENCIES = []
    MIME_BLACKLIST = ['filesystem']
    DESCRIPTION = 'search for IPs and URIs'
    VERSION = '0.4.2'

    def __init__(self, plugin_administrator, config=None, recursive=True):

        self.config = config

        self.ip_and_uri_finder = CommonAnalysisIPAndURIFinder()

        try:
            self.reader = geoip2.database.Reader(str(GEOIP_DATABASE_PATH))
        except FileNotFoundError:
            logging.error('could not load GeoIP database')
            self.reader = None

        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        result = self.ip_and_uri_finder.analyze_file(file_object.file_path, separate_ipv6=True)

        for key in ['uris', 'ips_v4', 'ips_v6']:
            result[key] = self._remove_duplicates(result[key])
        result['ips_v4'] = self._remove_blacklisted(result['ips_v4'], IP_V4_BLACKLIST)
        result['ips_v6'] = self._remove_blacklisted(result['ips_v6'], IP_V6_BLACKLIST)

        file_object.processed_analysis[self.NAME] = self._get_augmented_result(self.add_geo_uri_to_ip(result))

        return file_object

    def _get_augmented_result(self, result):
        result['summary'] = self._get_summary(result)
        result['system_version'] = ip_and_uri_finder_analysis.system_version
        return result

    def add_geo_uri_to_ip(self, result):
        for key in ['ips_v4', 'ips_v6']:
            result[key] = self.link_ips_with_geo_location(result[key])
        return result

    def find_geo_location(self, ip_address):
        response = self.reader.city(ip_address)
        return '{}, {}'.format(response.location.latitude, response.location.longitude)  # pylint: disable=no-member

    def link_ips_with_geo_location(self, ip_addresses):
        linked_ip_geo_list = []
        for ip in ip_addresses:
            try:
                ip_tuple = ip, self.find_geo_location(ip)
            except (AttributeError, AddressNotFoundError, FileNotFoundError, ValueError, InvalidDatabaseError) as exception:
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
    def _remove_duplicates(input_list):
        return list(set(input_list))

    @staticmethod
    def _remove_blacklisted(ip_list, blacklist):
        for ip, blacklist_entry in product(ip_list, blacklist):
            if search(blacklist_entry, ip):
                with suppress(ValueError):
                    ip_list.remove(ip)
        return ip_list
