from __future__ import annotations

import re
from re import Pattern
from typing import TYPE_CHECKING, Iterable, List

from pydantic import BaseModel, Field
from semver import Version

import config
from analysis.plugin import AnalysisPluginV0
from plugins.analysis.strings.internal.string_eval import calculate_relevance_score
from plugins.mime_blacklists import MIME_BLACKLIST_COMPRESSED

if TYPE_CHECKING:
    from io import FileIO

STRING_REGEXES = [
    (b'[\x09-\x0d\x20-\x7e]{$len,}', 'utf-8'),
    (b'(?:[\x09-\x0d\x20-\x7e]\x00){$len,}', 'utf-16'),
]


class StringMatch(BaseModel):
    string: str
    offset: int
    relevance: float


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        strings: List[StringMatch] = Field(description='An array of ASCII strings contained in this file.')

    def __init__(self):
        super().__init__(
            metadata=(
                self.MetaData(
                    name='printable_strings',
                    description=(
                        'Extracts printable strings from a file and assigns a relevance score based on a predefined '
                        'ruleset.'
                    ),
                    version=Version(1, 0, 0),
                    mime_blacklist=MIME_BLACKLIST_COMPRESSED,
                    Schema=self.Schema,
                )
            )
        )
        self.regexes = self._compile_regexes()

    def _compile_regexes(self) -> list[tuple[Pattern[bytes], str]]:
        min_length = getattr(config.backend.plugin.get(self.metadata.name, {}), 'min-length', 8)
        return [
            (re.compile(regex.replace(b'$len', str(min_length).encode())), encoding)
            for regex, encoding in STRING_REGEXES
        ]

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel]):
        del virtual_file_path, analyses
        return self.Schema(
            strings=[
                StringMatch(
                    offset=offset,
                    string=string,
                    relevance=calculate_relevance_score(string),
                )
                for offset, string in self._find_all_strings_and_offsets(file_handle.read())
            ]
        )

    def _find_all_strings_and_offsets(self, source: bytes) -> Iterable[tuple[int, str]]:
        for regex, encoding in self.regexes:
            yield from self._match_with_offset(regex, source, encoding)

    @staticmethod
    def _match_with_offset(regex: Pattern[bytes], source: bytes, encoding: str = 'utf-8') -> Iterable[tuple[int, str]]:
        for match in regex.finditer(source):
            yield match.start(), match.group().decode(encoding)
