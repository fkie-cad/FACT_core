import logging

from common_analysis_oms.oms import CommonAnalysisOMS

from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This Plugin creates several hashes of the file
    '''
    NAME = 'malware_scanner'
    DEPENDENCIES = []
    MIME_BLACKLIST = ['filesystem']
    VERSION = '0.3.1'
    DESCRIPTION = 'scan for known malware'
    FILE = __file__

    def additional_setup(self):
        self.oms = CommonAnalysisOMS()

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
        file_object.processed_analysis[self.NAME]['summary'] = self._get_summary(
            file_object.processed_analysis[self.NAME]
        )
        return file_object

    @staticmethod
    def _get_summary(results):
        summary = []
        if results['positives'] > 0:
            summary.append('Malware Found')
        return summary
