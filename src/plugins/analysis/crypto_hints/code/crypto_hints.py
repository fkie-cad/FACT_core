from __future__ import annotations

from typing import TYPE_CHECKING

import pydantic
from semver import Version

from analysis.plugin import AnalysisPluginV0, addons

if TYPE_CHECKING:
    import io

    import yara


def yara_match_to_dict_hex(match: yara.Match) -> dict:
    strings = [
        {
            'offset': int(string_instance.offset or 0),
            'name': str(string_match.identifier),
            'hex_value': string_instance.matched_data.hex() if string_instance.matched_data else '',
        }
        for string_match in match.strings
        for string_instance in string_match.instances
    ]

    return {
        'meta': {
            'open_source': match.meta.get('open_source'),
            'software_name': match.meta.get('software_name'),
            'website': match.meta.get('website'),
            'date': match.meta.get('date'),
            'author': match.meta.get('author'),
            'description': match.meta.get('description'),
        },
        'rule': match.rule,
        'strings': strings,
    }


class StringMatch(pydantic.BaseModel):
    """Represents one string matched by a rule"""

    offset: int
    name: str
    hex_value: str


class MatchMeta(pydantic.BaseModel):
    """Represents the metadata fields of a rule"""

    open_source: str | None = None
    software_name: str | None = None
    website: str | None = None
    date: str | None = None
    author: str | None = None
    description: str | None = None


class Match(pydantic.BaseModel):
    """Represents a single match of a YARA rule"""

    meta: MatchMeta
    rule: str
    strings: list[StringMatch]

    @classmethod
    def from_yara_match(cls, match: yara.Match) -> Match:
        strings = [
            StringMatch(
                offset=int(string_instance.offset or 0),
                name=str(string_match.identifier),
                hex_value=string_instance.matched_data.hex() if string_instance.matched_data else '',
            )
            for string_match in match.strings
            for string_instance in string_match.instances
        ]

        return cls(
            meta=MatchMeta(
                open_source=match.meta.get('open_source'),
                software_name=match.meta.get('software_name'),
                website=match.meta.get('website'),
                date=match.meta.get('date'),
                author=match.meta.get('author'),
                description=match.meta.get('description'),
            ),
            rule=match.rule,
            strings=strings,
        )


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(pydantic.BaseModel):
        """A dataclass for a List of found matches"""

        matches: list[Match]

    def __init__(self):
        metadata = self.MetaData(
            name='crypto_hints',
            description='find indicators of specific crypto algorithms',
            version=Version(0, 3, 0),
            Schema=AnalysisPlugin.Schema,
        )
        super().__init__(metadata=metadata)

        self._yara = addons.Yara(plugin=self)

    def summarize(self, result: Schema) -> list[str]:
        return [match.rule for match in result.matches]

    def analyze(self, file_handle: io.FileIO, virtual_file_path: dict, analyses: dict) -> Schema:
        del virtual_file_path, analyses
        return AnalysisPlugin.Schema(
            matches=[Match.from_yara_match(m) for m in self._yara.match(file_handle)],
        )
