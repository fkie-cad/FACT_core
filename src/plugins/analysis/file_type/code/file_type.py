from __future__ import annotations

import json
import typing
from pathlib import Path
from typing import List

import pydantic
from pydantic import Field
from semver import Version

from analysis.plugin import AnalysisPluginV0
from helperFunctions import magic
from helperFunctions.fileSystem import get_bin_dir

if typing.TYPE_CHECKING:
    import io


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(pydantic.BaseModel):
        mime: str = Field(
            description="The file's mimetype.",
        )
        full: str = Field(
            description="The file's full description.",
        )

    def __init__(self):
        try:
            version_file = Path(get_bin_dir()) / 'version.json'
            fw_magic_db_version = json.loads(version_file.read_text()).get('version')
        except (json.JSONDecodeError, FileNotFoundError):
            fw_magic_db_version = None
        super().__init__(
            metadata=AnalysisPluginV0.MetaData(
                name='file_type',
                description='identify the file type',
                version=Version(1, 0, 1),
                system_version=fw_magic_db_version,
                Schema=AnalysisPlugin.Schema,
            ),
        )

    def summarize(self, result: Schema) -> List[str]:
        return [result.mime]

    def analyze(self, file_handle: io.FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path, analyses

        return AnalysisPlugin.Schema(
            mime=magic.from_file(file_handle.name, mime=True),
            full=magic.from_file(file_handle.name, mime=False),
        )
