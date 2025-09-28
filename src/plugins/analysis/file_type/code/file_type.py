from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from magika import Magika
from pydantic import BaseModel, Field
from semver import Version

from analysis.plugin import AnalysisPluginV0
from helperFunctions import magic

if TYPE_CHECKING:
    import io


class MagikaResult(BaseModel):
    label: str
    mime: str
    group: str
    description: str
    is_text: bool
    confidence: float


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        mime: str = Field(
            description="The file's mimetype.",
        )
        full: str = Field(
            description="The file's full description.",
        )
        magika: Optional[MagikaResult] = Field(
            None,
            description="Output of google's deep learning file type detection tool magika.",
        )

    def __init__(self):
        self.magika = Magika()
        super().__init__(
            metadata=AnalysisPluginV0.MetaData(
                name='file_type',
                description='identify the file type',
                version=Version(1, 1, 0),
                Schema=AnalysisPlugin.Schema,
            ),
        )

    def summarize(self, result: Schema) -> List[str]:
        return [result.mime]

    def analyze(self, file_handle: io.FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path, analyses
        magika_result = self.magika.identify_path(file_handle.name)

        return AnalysisPlugin.Schema(
            mime=magic.from_file(file_handle.name, mime=True),
            full=magic.from_file(file_handle.name, mime=False),
            magika=MagikaResult(
                label=magika_result.output.label,
                mime=magika_result.output.mime_type,
                group=magika_result.output.group,
                description=magika_result.output.description,
                is_text=magika_result.output.is_text,
                confidence=magika_result.score,
            ),
        )
