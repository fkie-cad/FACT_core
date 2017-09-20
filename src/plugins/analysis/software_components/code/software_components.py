from analysis.YaraPluginBase import YaraBasePlugin
import re
from helperFunctions.dataConversion import make_unicode_string


class AnalysisPlugin(YaraBasePlugin):
    '''
    This plugin identifies software components
    '''
    NAME = 'software_components'
    DESCRIPTION = 'identify software components'
    VERSION = '0.3'
    FILE = __file__

    def process_object(self, file_object):
        file_object = super().process_object(file_object)
        if len(file_object.processed_analysis[self.NAME]) > 1:
            file_object.processed_analysis[self.NAME] = self.add_version_information(file_object.processed_analysis[self.NAME])
            file_object.processed_analysis[self.NAME]['summary'] = self._get_summary(file_object.processed_analysis[self.NAME])
        return file_object

    @staticmethod
    def get_version(input_string):
        regex = '\d+.\d+(.\d+)?(\w)?'
        pattern = re.compile(regex)
        version = pattern.search(input_string)
        if version is not None:
            return version.group(0)
        else:
            return ''

    def _get_summary(self, results):
        summary = set()
        for item in results:
            if item != 'summary':
                for version in results[item]['meta']['version']:
                    summary.add('{} {}'.format(results[item]['meta']['software_name'], version))
        summary = list(summary)
        summary.sort()
        return summary

    def add_version_information(self, results):
        for item in results:
            if item != 'summary':
                results[item] = self.get_version_for_component(results[item])
        return results

    def get_version_for_component(self, result):
        versions = set()
        for matched_string in result['strings']:
            offset, rule_string, match = matched_string
            match = make_unicode_string(match)
            versions.add(self.get_version(match))
        result['meta']['version'] = list(versions)
        return result
