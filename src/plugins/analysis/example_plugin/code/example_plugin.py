import io

import pydantic

from analysis.plugin.compat import AnalysisBasePluginAdapterMixin
from analysis.plugin import AnalysisPluginV0


class AnalysisPlugin(AnalysisPluginV0, AnalysisBasePluginAdapterMixin):
    class Schema(pydantic.BaseModel):
        number: int
        name: str
        first_byte: str
        virtual_file_path: dict
        dependant_analysis: dict

    def __init__(self):
        metadata = AnalysisPluginV0.MetaData(
            name='ExamplePlugin',
            description='An example description',
            version='0.0.0',
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

    def analyze(self, file_handle: io.FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        file_type_analysis = analyses['file_type']

        first_byte = file_handle.read(1)
        return AnalysisPlugin.Schema(
            number=42,
            name=file_handle.name,
            first_byte=first_byte.hex(),
            virtual_file_path=virtual_file_path,
            dependant_analysis=file_type_analysis,
        )
