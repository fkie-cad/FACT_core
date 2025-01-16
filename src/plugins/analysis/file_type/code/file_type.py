from __future__ import annotations

import typing
from typing import List

import pydantic
from pydantic import Field

from analysis.plugin import AnalysisPluginV0
from helperFunctions import magic

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
        super().__init__(
            metadata=AnalysisPluginV0.MetaData(
                name='file_type',
                description='identify the file type',
                version='1.0.0',
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
