import io
from pathlib import Path

import pydantic
from pydantic import Field
from semver import Version

from analysis.plugin import AnalysisFailedError, AnalysisPluginV0


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(pydantic.BaseModel):
        """Here goes the toplevel description of the plugin result"""

        # fmt: off
        number: int = Field(
            description=(
                'This is a description of the field number.\n'
                'In an actual plugin all fields must have a description.'
            ),
        )
        # fmt: on
        name: str
        first_byte: str
        virtual_file_path: dict
        dependant_analysis: dict

    def __init__(self):
        metadata = self.MetaData(
            name='ExamplePlugin',
            description='An example description',
            version=Version(0, 0, 0),
            Schema=AnalysisPlugin.Schema,
            # Note that you don't have to set these fields,
            # they are just here to show that you can.
            system_version=None,
            mime_blacklist=[],
            mime_whitelist=[],
            dependencies=['file_type'],
            timeout=5,
        )
        super().__init__(metadata=metadata)

    def summarize(self, result):
        del result
        return ['big-file', 'binary']

    def analyze(self, file_handle: io.FileIO, virtual_file_path: dict, analyses: dict) -> Schema:
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
