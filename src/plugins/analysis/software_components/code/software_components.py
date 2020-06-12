import os
import re
import sys
from pathlib import Path
from typing import List

from common_helper_files import get_dir_of_file

from analysis.YaraPluginBase import YaraBasePlugin
from helperFunctions.dataConversion import make_unicode_string
from helperFunctions.tag import TagColor
from objects.file import FileObject
from plugins.analysis.software_components.bin import OS_LIST

try:
    from ..internal.resolve_version_format_string import extract_data_from_ghidra
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from resolve_version_format_string import extract_data_from_ghidra

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
    VERSION = '0.4.1'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        file_object = super().process_object(file_object)
        analysis = file_object.processed_analysis[self.NAME]
        if len(analysis) > 1:
            analysis = self.add_version_information(analysis, file_object)
            analysis['summary'] = self._get_summary(analysis)

            self.add_os_key(file_object)
        return file_object

    @staticmethod
    def get_version(input_string: str, meta_dict: dict) -> str:
        if 'version_regex' in meta_dict:
            regex = meta_dict['version_regex'].replace('\\\\', '\\')
        else:
            regex = r'\d+.\d+(.\d+)?(\w)?'
        pattern = re.compile(regex)
        version = pattern.search(input_string)
        if version is not None:
            return version.group(0)
        return ''

    @staticmethod
    def _get_summary(results) -> List[str]:
        summary = set()
        for item in results:
            if item != 'summary':
                for version in results[item]['meta']['version']:
                    summary.add('{} {}'.format(results[item]['meta']['software_name'], version))
        return sorted(summary)

    def add_version_information(self, results, file_object: FileObject):
        for item in results:
            if item != 'summary':
                results[item] = self.get_version_for_component(results[item], file_object)
        return results

    def get_version_for_component(self, result, file_object: FileObject):
        versions = set()
        for matched_string in result['strings']:
            match = matched_string[2]
            match = make_unicode_string(match)
            versions.add(self.get_version(match, result['meta']))
        if result['meta'].get('format_string'):
            key_strings = [s.decode() for _, _, s in result['strings'] if b'%s' in s]
            if key_strings:
                versions.update(extract_data_from_ghidra(file_object.binary, key_strings))
        if '' in versions and len(versions) > 1:  # if there are actual version results, remove the "empty" result
            versions.remove('')
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
