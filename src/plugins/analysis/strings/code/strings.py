from typing import List, Tuple

from analysis.PluginBase import AnalysisBasePlugin
from re import finditer


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Extracts all printable Strings
    '''
    NAME = 'printable_strings'
    DEPENDENCIES = []
    DESCRIPTION = 'extracts strings and their offsets from the files consisting of printable characters'
    VERSION = '0.3.3'

    STRING_REGEXES = [
        '[\x09-\x0d\x20-\x7e]{{{},}}',  # 8 bit printable strings
        '(?:[\x09-\x0d\x20-\x7e]\x00){{{},}}'  # 16 bit printable strings
    ]

    def __init__(self, plugin_administrator, config=None, recursive=True, plugin_path=__file__):
        '''
        recursive flag: If True recursively analyze included files
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=plugin_path)

    def process_object(self, file_object):
        strings, offsets = self._get_strings_and_offsets(file_object.binary)
        file_object.processed_analysis[self.NAME] = {
            'strings': strings,
            'offsets': offsets
        }
        return file_object

    def _get_strings_and_offsets(self, binary):
        min_length = self.config[self.NAME]['min_length']
        strings, offsets = self._find_all_strings_and_offsets(binary, min_length)
        return strings, offsets

    def _find_all_strings_and_offsets(self, source: bytes, min_length: int) -> Tuple[List[str], List[Tuple[int, str]]]:
        strings_with_offset = []
        for regex in self.STRING_REGEXES:
            strings_with_offset.extend(self._match_with_offset(regex.format(min_length), source))
        return self._get_list_of_unique_strings(strings_with_offset), strings_with_offset

    @staticmethod
    def _match_with_offset(regex: str, source: bytes) -> List[Tuple[int, str]]:
        result = []
        for match in finditer(regex.encode(), source):
            result.append((match.start(), match.group().decode()))
        return result

    @staticmethod
    def _get_list_of_unique_strings(strings_with_offset: List[Tuple[int, str]]) -> List[str]:
        return sorted(list(set(tuple(zip(*strings_with_offset))[1]))) if strings_with_offset else []
