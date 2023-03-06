from __future__ import annotations

import re
from re import Pattern

import config
from analysis.PluginBase import AnalysisBasePlugin
from plugins.mime_blacklists import MIME_BLACKLIST_COMPRESSED


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Extracts all printable Strings
    '''

    NAME = 'printable_strings'
    DEPENDENCIES = []
    MIME_BLACKLIST = MIME_BLACKLIST_COMPRESSED
    DESCRIPTION = 'extracts strings and their offsets from the files consisting of printable characters'
    VERSION = '0.3.4'
    FILE = __file__

    STRING_REGEXES = [
        (b'[\x09-\x0d\x20-\x7e]{$len,}', 'utf-8'),
        (b'(?:[\x09-\x0d\x20-\x7e]\x00){$len,}', 'utf-16'),
    ]

    def additional_setup(self):
        self.regexes = self._compile_regexes()

    def _compile_regexes(self) -> list[tuple[Pattern[bytes], str]]:
        min_length = getattr(config.backend.plugin.get(self.NAME, {}), 'min-length', 8)
        return [
            (re.compile(regex.replace(b'$len', str(min_length).encode())), encoding)
            for regex, encoding in self.STRING_REGEXES
        ]

    def process_object(self, file_object):
        strings, offsets = self._find_all_strings_and_offsets(file_object.binary)
        file_object.processed_analysis[self.NAME] = {'strings': strings, 'offsets': offsets}
        return file_object

    def _find_all_strings_and_offsets(self, source: bytes) -> tuple[list[str], list[tuple[int, str]]]:
        strings_with_offset = []
        for regex, encoding in self.regexes:
            strings_with_offset.extend(self._match_with_offset(regex, source, encoding))
        return self._get_list_of_unique_strings(strings_with_offset), strings_with_offset

    @staticmethod
    def _match_with_offset(regex: Pattern[bytes], source: bytes, encoding: str = 'utf-8') -> list[tuple[int, str]]:
        return [(match.start(), match.group().decode(encoding)) for match in regex.finditer(source)]

    @staticmethod
    def _get_list_of_unique_strings(strings_with_offset: list[tuple[int, str]]) -> list[str]:
        return sorted(list(set(tuple(zip(*strings_with_offset))[1]))) if strings_with_offset else []
