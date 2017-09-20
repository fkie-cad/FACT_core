import os

from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder, ip_and_uri_finder_analysis
import logging
from analysis.PluginBase import BasePlugin
from helperFunctions.fileSystem import get_absolute_path, get_src_dir


class AnalysisPlugin(BasePlugin):
    '''
    This plug-in finds IPs and URIs
    '''
    NAME = 'ip_and_uri_finder'
    DEPENDENCYS = []
    VERSION = '0.3'
    DESCRIPTION = 'search for IPs and URIs'
    FILE = __file__
    VERSION = ip_and_uri_finder_analysis.system_version

    def __init__(self, plugin_adminstrator, config=None, recursive=True):

        self.config = config

        # additional init stuff can go here
        self.IPAndURIFinder = CommonAnalysisIPAndURIFinder()

        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        result = self.IPAndURIFinder.analyze_file(file_object.file_path, separate_ipv6=True)
        logging.debug(result)
        for key in ['uris', 'ips_v4', 'ips_v6']:
            result[key] = self._remove_duplicates(result[key])
        file_object.processed_analysis[self.NAME] = result
        file_object.processed_analysis[self.NAME]['summary'] = self._get_summary(result)
        return file_object

    @staticmethod
    def _get_summary(results):
        summary = []
        for key in ['uris', 'ips_v4', 'ips_v6']:
            summary.extend(results[key])
        return summary

    @staticmethod
    def _remove_duplicates(l):
        return list(set(l))
