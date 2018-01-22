import os
import sys

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.strings import find_all_strings


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Extracts all printable Strings
    '''
    NAME = 'printable_strings'
    DEPENDENCIES = []
    DESCRIPTION = 'extracts strings from the files consisting of printable characters'
    VERSION = '0.2'

    def __init__(self, plugin_administrator, config=None, recursive=True, plugin_path=__file__):
        '''
        recursive flag: If True recursively analyze included files
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        self.config = config

        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        result = {}
        result['strings'] = find_all_strings(file_object.binary, min_length=self.config[self.NAME]['min_length'])
        file_object.processed_analysis[self.NAME] = result
        return file_object

    def _get_summary(self, match_dict):
        return list(match_dict.keys())
