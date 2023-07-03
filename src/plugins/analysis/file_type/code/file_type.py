from fact_helper_file import get_file_type_from_path
import pydantic

from analysis.plugin import AnalysisPluginV0
from analysis.plugin.compat import AnalysisBasePluginAdapterMixin

import io
from typing import List


class AnalysisPlugin(AnalysisPluginV0, AnalysisBasePluginAdapterMixin):
    class Schema(pydantic.BaseModel):
        #: The files mimetype
        mime: str
        #: The files full description
        full: str

    def __init__(self):
        super().__init__(
            metadata=AnalysisPluginV0.MetaData(
                name='file_type',
                description='identify the file type',
                version='1.1.0',
                Schema=AnalysisPlugin.Schema,
            ),
        )

    def summarize(self, result: Schema) -> List[str]:
        return [result.mime]

    def analyze(self, file_handle: io.FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path, analyses

        file_dict = get_file_type_from_path(file_handle.name)

        return AnalysisPlugin.Schema(
            mime=file_dict['mime'],
            full=file_dict['full'],
        )
