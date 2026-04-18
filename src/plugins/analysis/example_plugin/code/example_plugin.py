from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field
from semver import Version

from analysis.plugin.plugin import AnalysisFailedError, AnalysisPluginV0

if TYPE_CHECKING:
    import io


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        """Here goes the toplevel description of the plugin result"""

        number: int = Field(
            description=(
                'This is a description of the field "number".\n'
                'In an actual plugin all fields should have a description.'
            ),
        )
        name: str
        first_byte: str
        virtual_file_path: dict
        dependant_analysis: dict

    def __init__(self):
        metadata = self.MetaData(
            # mandatory fields:
            name='ExamplePlugin',
            description='An example description',
            version=Version(0, 0, 0),
            Schema=self.Schema,
            # optional fields:
            system_version=None,
            mime_blacklist=[],
            mime_whitelist=[],
            dependencies=['file_type'],
            timeout=5,
        )
        super().__init__(metadata=metadata)

    def summarize(self, result: Schema) -> list[str]:
        del result
        return ['big-file', 'binary']

    def analyze(self, file_handle: io.FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel]) -> Schema:
        first_byte = file_handle.read(1)
        if first_byte == b'\xff':
            raise AnalysisFailedError('reason for fail')
        if first_byte == b'\xee':
            raise Exception('Unexpected exception occurred.')
        return AnalysisPlugin.Schema(
            number=42,
            name=Path(file_handle.name).name,
            first_byte=first_byte.hex(),
            virtual_file_path=virtual_file_path,
            dependant_analysis=analyses['file_type'].model_dump(),
        )
