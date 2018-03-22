import logging
import os
from sys import exc_info

import geoip2.database
from common_helper_files import get_dir_of_file

from analysis.PluginBase import AnalysisBasePlugin
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder, ip_and_uri_finder_analysis

geoip_database_path = os.path.join(get_dir_of_file(__file__), '../bin/GeoLite2-City/GeoLite2-City.mmdb')


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This plug-in finds IPs and URIs
    '''
    NAME = 'ip_and_uri_finder'
    DEPENDENCIES = []
    VERSION = '0.3'
    DESCRIPTION = 'search for IPs and URIs'
    FILE = __file__
    VERSION = ip_and_uri_finder_analysis.system_version

    def __init__(self, plugin_administrator, config=None, recursive=True):

        self.config = config

        # additional init stuff can go here
        self.IPAndURIFinder = CommonAnalysisIPAndURIFinder()

        self.reader = geoip2.database.Reader(geoip_database_path)

        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        result = self.IPAndURIFinder.analyze_file(file_object.file_path, separate_ipv6=True)
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
        try:
            response = self.reader.city(ip_address)
            latitude = response.location.latitude
            longitude = response.location.longitude
        except Exception as e:
            logging.error("Geo Location of IP: {} {}".format(exc_info()[0].__name__, e))
            return ""
        return (latitude, longitude)

    def link_ips_with_geo_location(self, ip_adresses):
        linked_ip_geo_list = []
        for ip in ip_adresses:
            link = {ip: str(self.find_geo_location(ip))}
            linked_ip_geo_list.append(link)
        return linked_ip_geo_list

    def _get_summary(self, results):
        summary = []
        for key in ['uris']:
            summary.extend(results[key])
        for key in ['ips_v4', 'ips_v6']:
            for i in results[key]:
                summary.extend(i)
        return summary

    @staticmethod
    def _remove_duplicates(l):
        return list(set(l))
