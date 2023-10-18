from fact_helper_file import get_file_type_from_path
import pydantic
from pydantic import Field

from analysis.plugin import AnalysisPluginV0
from analysis.plugin.compat import AnalysisBasePluginAdapterMixin

import io
from typing import List

from helperFunctions.virtual_file_path import VfpDict


class AnalysisPlugin(AnalysisPluginV0, AnalysisBasePluginAdapterMixin):
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

    def analyze(self, file_handle: io.FileIO, virtual_file_path: VfpDict, analyses: dict) -> Schema:
        del virtual_file_path, analyses

        file_dict = get_file_type_from_path(file_handle.name)

        return AnalysisPlugin.Schema(
            mime=file_dict['mime'],
            full=file_dict['full'],
        )
