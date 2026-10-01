from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING

from magika import Magika
from pydantic import BaseModel, Field
from semver import Version

from analysis.plugin import AnalysisPluginV0
from helperFunctions import magic

if TYPE_CHECKING:
    import io


@cache
def _get_magika() -> Magika:
    # Magika uses an onnxruntime session which segfaults if it is destroyed in a forked child process (e.g. if the GC
    # of the child collects a reference cycle containing the session). Therefore, the instance is created lazily and
    # kept alive for the lifetime of the process (it is never garbage collected).
    return Magika()


class MagikaResult(BaseModel):
    label: str = Field(
        description='simple to understand content type.',
    )
    mime: str
    group: str = Field(
        description="broader category for lable e.g., 'code', 'document', 'media'....",
    )
    description: str
    is_text: bool
    confidence: float


class AnalysisPlugin(AnalysisPluginV0):
    """Plugin for analyzing the file type of a document."""

    class Schema(BaseModel):
        """Schema for frontend output."""

        mime: str = Field(
            description="The file's mimetype.",
        )
        full: str = Field(
            description="The file's full description.",
        )
        magika: MagikaResult | None = Field(
            None,
            description="Output of google's deep learning file type detection tool magika.",
        )

    def __init__(self):
        super().__init__(
            metadata=self.MetaData(
                name='file_type',
                description='identify the file type',
                version=Version(1, 1, 0),
                Schema=AnalysisPlugin.Schema,
            ),
        )

    def summarize(self, result: Schema) -> list[str]:
        return [result.mime]

    def analyze(self, file_handle: io.FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path, analyses
        magika_result = _get_magika().identify_path(file_handle.name)

        return AnalysisPlugin.Schema(
            mime=magic.from_file(file_handle.name, mime=True),
            full=magic.from_file(file_handle.name, mime=False),
            magika=MagikaResult(
                label=magika_result.output.label,
                mime=magika_result.output.mime_type,
                group=magika_result.output.group,
                description=magika_result.output.description,
                is_text=magika_result.output.is_text,
                confidence=round(magika_result.score, 4),
            ),
        )
