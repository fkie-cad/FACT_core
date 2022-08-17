import logging
from contextlib import suppress
from itertools import product
from pathlib import Path
from re import search

import geoip2.database
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder
from geoip2.errors import AddressNotFoundError
from maxminddb.errors import InvalidDatabaseError

from analysis.PluginBase import AnalysisBasePlugin

GEOIP_DATABASE_PATH = Path(__file__).parent.parent / 'bin/GeoLite2-City/GeoLite2-City.mmdb'

IP_V4_BLACKLIST = [
    r'127.0.[0-9]+.1',  # localhost
    r'255.[0-9]+.[0-9]+.[0-9]+'  # subnet masks
]
IP_V6_BLACKLIST = [  # trivial addresses
    r'^[0-9A-Za-z]::$',
    r'^::[0-9A-Za-z]$',
    r'^[0-9A-Za-z]::[0-9A-Za-z]$',
    r'^::$'
]


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'ip_and_uri_finder'
    DEPENDENCIES = []
    MIME_WHITELIST = [
        'text/plain',
        'application/octet-stream',
        'application/x-executable',
        'application/x-object',
        'application/x-sharedlib',
        'application/x-dosexec'
    ]
    DESCRIPTION = 'Search file for IP addresses and URIs based on regular expressions.'
    VERSION = '0.4.2'
    FILE = __file__

    def additional_setup(self):
        self.ip_and_uri_finder = CommonAnalysisIPAndURIFinder()
        try:
            self.reader = geoip2.database.Reader(str(GEOIP_DATABASE_PATH))
        except FileNotFoundError:
            logging.error('could not load GeoIP database')
            self.reader = None

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
        result['system_version'] = self.ip_and_uri_finder.system_version
        return result

    def add_geo_uri_to_ip(self, result):
        for key in ['ips_v4', 'ips_v6']:
            result[key] = self.link_ips_with_geo_location(result[key])
        return result

    def find_geo_location(self, ip_address):
        response = self.reader.city(ip_address)
        return f'{response.location.latitude}, {response.location.longitude}'  # pylint: disable=no-member

    def link_ips_with_geo_location(self, ip_addresses):
        linked_ip_geo_list = []
        for ip in ip_addresses:
            try:
                ip_tuple = ip, self.find_geo_location(ip)
            except (
                AttributeError, AddressNotFoundError, FileNotFoundError, ValueError, InvalidDatabaseError,
            ) as exception:
                logging.debug(f'Error during {self.NAME} analysis: {str(exception)}', exc_info=True)
                ip_tuple = ip, ''
            linked_ip_geo_list.append(ip_tuple)
        return linked_ip_geo_list

    @staticmethod
    def _get_summary(results):
        summary = []
        summary.extend(results['uris'])
        for key in ['ips_v4', 'ips_v6']:
            for ip, *_ in results[key]:  # IP results come in tuples (ip, latitude, longitude)
                summary.append(ip)
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
