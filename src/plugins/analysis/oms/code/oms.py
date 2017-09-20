from common_analysis_oms.oms import CommonAnalysisOMS
import logging

from analysis.PluginBase import BasePlugin


class AnalysisPlugin(BasePlugin):
    '''
    This Plugin creates several hashes of the file
    '''
    NAME = "malware_scanner"
    DEPENDENCYS = []
    VERSION = "0.3"
    DESCRIPTION = "scan for known malware"

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        '''
        recursive flag: If True recursively analyze included files
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        self.config = config

        # additional init stuff can go here
        self.oms = CommonAnalysisOMS()

        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        '''
        This function must be implemented by the plugin.
        Analysis result must be a dict stored in file_object.processed_analysis[self.NAME]
        If you want to propagate results to parent objects store a list of strings 'summary' entry of your result dict
        '''
        result = self.oms.analyze_file(file_object.file_path)
        logging.debug(result)
        logging.debug(type(result))
        file_object.processed_analysis[self.NAME] = result
        file_object.processed_analysis[self.NAME]['summary'] = self._get_summary(file_object.processed_analysis[self.NAME])
        return file_object

    @staticmethod
    def _get_summary(results):
        summary = []
        if results['positives'] > 0:
            summary.append('Malware Found')
        return summary
