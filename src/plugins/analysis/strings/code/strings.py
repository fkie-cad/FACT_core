import re
from typing import List, Pattern, Tuple

from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Extracts all printable Strings
    '''
    NAME = 'printable_strings'
    DEPENDENCIES = []
    MIME_BLACKLIST = ['application/gzip', 'application/gzip', 'application/x-7z-compressed', 'application/x-tar', 'application/x-xz', 'application/zip']
    DESCRIPTION = 'extracts strings and their offsets from the files consisting of printable characters'
    VERSION = '0.3.4'

    STRING_REGEXES = [
        (b'[\x09-\x0d\x20-\x7e]{$len,}', 'utf-8'),
        (b'(?:[\x09-\x0d\x20-\x7e]\x00){$len,}', 'utf-16'),
    ]
    FALLBACK_MIN_LENGTH = '8'

    def __init__(self, plugin_administrator, config=None, recursive=True, plugin_path=__file__):
        '''
        recursive flag: If True recursively analyze included files
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        self.config = config
        self.regexes = self._compile_regexes()
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=plugin_path)

    def _compile_regexes(self) -> List[Tuple[Pattern[bytes], str]]:
        min_length = self._get_min_length_from_config()
        return [
            (re.compile(regex.replace(b'$len', min_length.encode())), encoding)
            for regex, encoding in self.STRING_REGEXES
        ]

    def _get_min_length_from_config(self):
        try:
            min_length = self.config[self.NAME]['min_length']
        except KeyError:
            min_length = self.FALLBACK_MIN_LENGTH
        return min_length

    def process_object(self, file_object):
        strings, offsets = self._find_all_strings_and_offsets(file_object.binary)
        file_object.processed_analysis[self.NAME] = {
            'strings': strings,
            'offsets': offsets
        }
        return file_object

    def _find_all_strings_and_offsets(self, source: bytes) -> Tuple[List[str], List[Tuple[int, str]]]:
        strings_with_offset = []
        for regex, encoding in self.regexes:
            strings_with_offset.extend(self._match_with_offset(regex, source, encoding))
        return self._get_list_of_unique_strings(strings_with_offset), strings_with_offset

    @staticmethod
    def _match_with_offset(regex: Pattern[bytes], source: bytes, encoding: str = 'utf-8') -> List[Tuple[int, str]]:
        return [
            (match.start(), match.group().decode(encoding))
            for match in regex.finditer(source)
        ]

    @staticmethod
    def _get_list_of_unique_strings(strings_with_offset: List[Tuple[int, str]]) -> List[str]:
        return sorted(list(set(tuple(zip(*strings_with_offset))[1]))) if strings_with_offset else []
