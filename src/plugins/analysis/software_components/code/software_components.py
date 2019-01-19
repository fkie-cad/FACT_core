import os
import re

from common_helper_files import get_dir_of_file

from analysis.YaraPluginBase import YaraBasePlugin
from helperFunctions.dataConversion import make_unicode_string
from helperFunctions.tag import TagColor
from plugins.analysis.software_components.bin import OS_LIST

SIGNATURE_DIR = os.path.join(get_dir_of_file(__file__), '../signatures')


class AnalysisPlugin(YaraBasePlugin):
    '''
    This plugin identifies software components

    Credits:
    OS Tagging functionality created by Roman Konertz during Firmware Bootcamp WT17/18 at University of Bonn
    Maintained by Fraunhofer FKIE
    '''
    NAME = 'software_components'
    DESCRIPTION = 'identify software components'
    MIME_BLACKLIST = ['audio', 'filesystem', 'image', 'video']
    VERSION = '0.3.2'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        file_object = super().process_object(file_object)
        analysis = file_object.processed_analysis[self.NAME]
        if len(analysis) > 1:
            analysis = self.add_version_information(analysis)
            analysis['summary'] = self._get_summary(analysis)

            self.add_os_key(file_object)
        return file_object

    @staticmethod
    def get_version(input_string: str, meta_dict: dict) -> str:
        if 'version_regex' in meta_dict:
            regex = meta_dict['version_regex'].replace('\\\\', '\\')
        else:
            regex = '\\d+.\\d+(.\\d+)?(\\w)?'
        pattern = re.compile(regex)
        version = pattern.search(input_string)
        if version is not None:
            return version.group(0)
        else:
            return ''

    @staticmethod
    def _get_summary(results):
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
            match = matched_string[2]
            match = make_unicode_string(match)
            versions.add(self.get_version(match, result['meta']))
        result['meta']['version'] = list(versions)
        return result

    def add_os_key(self, file_object):
        for entry in file_object.processed_analysis[self.NAME]['summary']:
            for os_ in OS_LIST:
                if entry.find(os_) != -1:
                    if self._entry_has_no_trailing_version(entry, os_):
                        self.add_analysis_tag(file_object, 'OS', entry, TagColor.GREEN, True)
                    else:
                        self.add_analysis_tag(file_object, 'OS', os_, TagColor.GREEN, False)
                        self.add_analysis_tag(file_object, 'OS Version', entry, TagColor.GREEN, True)

    @staticmethod
    def _entry_has_no_trailing_version(entry, os_string):
        return os_string.strip() == entry.strip()
