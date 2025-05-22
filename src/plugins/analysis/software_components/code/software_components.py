from __future__ import annotations

import re
import string
from typing import TYPE_CHECKING, List, Optional

from pydantic import BaseModel, Field
from semver import Version

import config
from analysis.plugin import AnalysisPluginV0, Tag, addons
from analysis.plugin.compat import AnalysisBasePluginAdapterMixin
from helperFunctions.tag import TagColor
from plugins.analysis.software_components.bin import OS_LIST
from plugins.mime_blacklists import MIME_BLACKLIST_NON_EXECUTABLE

from ..internal.resolve_version_format_string import extract_data_from_ghidra

if TYPE_CHECKING:
    from io import FileIO

    import yara


class SoftwareMatch(BaseModel):
    name: str
    versions: List[str]
    rule: str = Field(description='Matching YARA rule name')
    matching_strings: List[MatchingString]
    description: Optional[str] = None
    open_source: Optional[bool] = None
    website: Optional[str] = Field(None, description='Website URL of the software')


class MatchingString(BaseModel):
    string: str
    offset: int
    identifier: str = Field(description='Identifier of the rule that this string matched (e.g. "$a")')


class AnalysisPlugin(AnalysisPluginV0, AnalysisBasePluginAdapterMixin):
    class Schema(BaseModel):
        software_components: List[SoftwareMatch]

    def __init__(self):
        super().__init__(
            metadata=(
                self.MetaData(
                    name='software_components',
                    description='identify software components',
                    mime_blacklist=MIME_BLACKLIST_NON_EXECUTABLE,
                    version=Version(1, 0, 0),
                    Schema=self.Schema,
                )
            )
        )
        self._yara = addons.Yara(plugin=self)

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel]) -> Schema:
        del virtual_file_path, analyses
        return self.Schema(
            software_components=[
                SoftwareMatch(
                    name=match.meta.get('software_name'),
                    rule=match.rule,
                    matching_strings=_get_matching_strings(match),
                    versions=get_version_for_component(match, file_handle),
                    description=match.meta.get('description'),
                    website=match.meta.get('website'),
                    open_source=match.meta.get('open_source'),
                )
                for match in self._yara.match(file_handle)
            ]
        )

    def summarize(self, result: Schema) -> list[str]:
        summary = set()
        for software in result.software_components:
            if software.versions:
                for version in software.versions:
                    summary.add(f'{software.name} {version}')
            else:
                summary.add(software.name)
        return sorted(summary)

    def get_tags(self, result: Schema, summary: list[str]) -> list[Tag]:
        del result
        tags = []
        for entry in summary:
            for os_ in OS_LIST:
                if entry.find(os_) != -1:
                    if _entry_has_no_trailing_version(entry, os_):
                        tags.append(Tag(name='OS', value=entry, color=TagColor.GREEN, propagate=True))
                    else:
                        tags.append(Tag(name='OS', value=os_, color=TagColor.GREEN, propagate=False))
                        tags.append(Tag(name='OS Version', value=entry, color=TagColor.GREEN, propagate=True))
        return tags


def _get_matching_strings(match: yara.Match) -> list[MatchingString]:
    return [
        MatchingString(
            string=instance.matched_data.decode(errors='replace'),
            offset=instance.offset,
            identifier=_string.identifier,
        )
        for _string in match.strings  # type: yara.StringMatch
        for instance in _string.instances  # type: yara.StringMatchInstance
    ]


def get_version_for_component(match: yara.Match, file: FileIO) -> list[str]:
    matching_strings = _get_strings_from_match(match)
    versions = {get_version(matching_str, match.meta) for matching_str in matching_strings}
    if any(k in match.meta for k in ('format_string', '_version_function')):
        if match.meta.get('format_string'):
            input_data = {
                'mode': 'format_string',
                'key_string_list': [s for s in matching_strings if '%s' in s],
            }
        else:
            input_data = {
                'mode': 'version_function',
                'function_name': match.meta['_version_function'],
            }
        versions.update(extract_data_from_ghidra(file.name, input_data, config.backend.docker_mount_base_dir))
    return [v for v in versions if v]


def get_version(input_string: str, meta_dict: dict) -> str | None:
    if 'version_regex' in meta_dict:
        regex = meta_dict['version_regex'].replace('\\\\', '\\')
    else:
        regex = r'\d+.\d+(.\d+)?(\w)?'
    pattern = re.compile(regex)
    version = pattern.search(input_string)
    if version is not None:
        return _strip_leading_zeroes(version.group(0))
    return None


def _get_strings_from_match(match: yara.Match) -> list[str]:
    return [
        instance.matched_data.decode(errors='replace').strip()
        for string_match in match.strings
        for instance in string_match.instances
    ]


def _entry_has_no_trailing_version(entry, os_string):
    return os_string.strip() == entry.strip()


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
