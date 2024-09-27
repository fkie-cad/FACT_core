from __future__ import annotations

import re
import string
from typing import TYPE_CHECKING

import config
from analysis.YaraPluginBase import YaraBasePlugin
from helperFunctions.data_conversion import make_unicode_string
from helperFunctions.tag import TagColor
from plugins.analysis.software_components.bin import OS_LIST
from plugins.mime_blacklists import MIME_BLACKLIST_NON_EXECUTABLE

from ..internal.resolve_version_format_string import extract_data_from_ghidra

if TYPE_CHECKING:
    from objects.file import FileObject


class AnalysisPlugin(YaraBasePlugin):
    """
    This plugin identifies software components

    Credits:
    OS Tagging functionality created by Roman Konertz during Firmware Bootcamp WT17/18 at University of Bonn
    Maintained by Fraunhofer FKIE
    """

    NAME = 'software_components'
    DESCRIPTION = 'identify software components'
    MIME_BLACKLIST = MIME_BLACKLIST_NON_EXECUTABLE
    VERSION = '0.5.1'
    FILE = __file__

    def process_object(self, file_object):
        file_object = super().process_object(file_object)
        analysis = file_object.processed_analysis[self.NAME]
        if len(analysis) > 1:
            analysis = self.add_version_information(analysis, file_object)
            analysis['summary'] = self._get_summary(analysis)

            self.add_os_key(file_object)
        return file_object

    def get_version(self, input_string: str, meta_dict: dict) -> str:
        if 'version_regex' in meta_dict:
            regex = meta_dict['version_regex'].replace('\\\\', '\\')
        else:
            regex = r'\d+.\d+(.\d+)?(\w)?'
        pattern = re.compile(regex)
        version = pattern.search(input_string)
        if version is not None:
            return self._strip_leading_zeroes(version.group(0))
        return ''

    @staticmethod
    def _get_summary(results: dict) -> list[str]:
        summary = set()
        for key, result in results.items():
            if key != 'summary':
                software = result['meta']['software_name']
                for version in result['meta']['version']:
                    summary.add(f'{software} {version}')
        return sorted(summary)

    def add_version_information(self, results, file_object: FileObject):
        for item in results:
            if item != 'summary':
                results[item] = self.get_version_for_component(results[item], file_object)
        return results

    def get_version_for_component(self, result, file_object: FileObject):
        versions = set()
        for matched_string in result['strings']:
            match = matched_string[2].strip()
            match = make_unicode_string(match)
            versions.add(self.get_version(match, result['meta']))
        if any(k in result['meta'] for k in ('format_string', '_version_function')):
            if result['meta'].get('format_string'):
                input_data = {
                    'mode': 'format_string',
                    'key_string_list': [s for _, _, s in result['strings'] if '%s' in s],
                }
            else:
                input_data = {
                    'mode': 'version_function',
                    'function_name': result['meta']['_version_function'],
                }
            versions.update(
                extract_data_from_ghidra(file_object.file_path, input_data, config.backend.docker_mount_base_dir)
            )
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

    @staticmethod
    def _strip_leading_zeroes(version_string: str) -> str:
        prefix, suffix = '', ''
        while version_string and version_string[0] not in string.digits:
            prefix += version_string[0]
            version_string = version_string[1:]
        while version_string and version_string[-1] not in string.digits:
            suffix = version_string[-1] + suffix
            version_string = version_string[:-1]
        elements = []
        for element in version_string.split('.'):
            try:
                elements.append(str(int(element)))
            except ValueError:
                elements.append(element)
        return prefix + '.'.join(elements) + suffix
