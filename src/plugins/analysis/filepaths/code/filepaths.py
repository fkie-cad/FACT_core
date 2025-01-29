from __future__ import annotations

from typing import TYPE_CHECKING, List

import pydantic
from pydantic import Field
from semver import Version

import config
from analysis.plugin import AnalysisPluginV0, addons
from plugins.mime_blacklists import MIME_BLACKLIST_COMPRESSED

if TYPE_CHECKING:
    import io


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(pydantic.BaseModel):
        filepaths: List[str] = Field(description='Array of file paths that were referenced in the file')

    def __init__(self):
        super().__init__(
            metadata=(
                self.MetaData(
                    name='filepaths',
                    description='find all referenced file paths in files',
                    mime_blacklist=MIME_BLACKLIST_COMPRESSED,
                    version=Version(0, 1, 0),
                    Schema=AnalysisPlugin.Schema,
                )
            )
        )
        self._yara = addons.Yara(plugin=self)
        self.min_length = getattr(config.backend.plugin.get(self.metadata.name, {}), 'min-length', 5)

    def summarize(self, result):
        return ['filepaths'] if result.filepaths else []

    def analyze(self, file_handle: io.FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path, analyses
        unfiltered_strings = [
            (matched_string, instance.offset)
            for match in self._yara.match(file_handle)
            for string in match.strings
            for instance in string.instances
            if len(matched_string := _remove_quotes(instance.matched_data.decode(errors='ignore'))) >= self.min_length
        ]
        return AnalysisPlugin.Schema(
            filepaths=_remove_duplicate_paths(unfiltered_strings),
        )


def _remove_duplicate_paths(paths: list[tuple[str, int]]) -> list[str]:
    """
    There can be multiple instances of the same path at different offsets, which makes things a bit complicated.
    """
    offsets_by_path = {}
    for path, offset in paths:
        offsets_by_path.setdefault(path, []).append(offset)

    paths_without_duplicates = set()
    for path, offsets in offsets_by_path.items():
        if not all(
            any(
                _paths_overlap(other_path, other_offset, path, offset)
                for other_path in set(offsets_by_path) - {path}
                for other_offset in offsets_by_path[other_path]
            )
            for offset in offsets
        ):
            paths_without_duplicates.add(path)
    return list(paths_without_duplicates)


def _paths_overlap(path: str, offset: int, included_path: str, included_offset: int) -> bool:
    """
    YARA matches include overlaps like e.g.
        0 /foo/bar.sh
        4 /bar.sh
    We want to find and remove those.
    """
    return path.endswith(included_path) and offset == included_offset - (len(path) - len(included_path))


def _remove_quotes(string: str) -> str:
    if (string[-1] == '"' and string[0] == '"') or (string[-1] == "'" and string[0] == "'"):
        string = string[1:-1]
    return string
