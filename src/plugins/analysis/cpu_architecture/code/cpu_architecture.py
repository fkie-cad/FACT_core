from __future__ import annotations

from typing import TYPE_CHECKING, List

from pydantic import BaseModel
from semver import Version

from analysis.plugin import AnalysisPluginV0
from plugins.analysis.cpu_architecture.internal import dt, elf, kconfig, metadata

if TYPE_CHECKING:
    from io import FileIO


class Architecture(BaseModel):
    value: str
    detection_method: str


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        architectures: List[Architecture]

    def __init__(self):
        super().__init__(
            metadata=(
                self.MetaData(
                    name='cpu_architecture',
                    description='identify CPU architecture',
                    mime_blacklist=[
                        'application/msword',
                        'application/pdf',
                        'application/postscript',
                        'application/x-dvi',
                        'application/x-httpd-php',
                        'application/xhtml+xml',
                        'application/xml',
                        'image',
                        'video',
                    ],
                    dependencies=['file_type', 'kernel_config', 'device_tree'],
                    version=Version(1, 0, 0),
                    Schema=self.Schema,
                )
            )
        )

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel]) -> Schema:
        del virtual_file_path

        arch_dict = construct_result(analyses, file_handle.name)
        return self.Schema(
            architectures=[Architecture(value=value, detection_method=method) for value, method in arch_dict.items()]
        )

    def summarize(self, result: Schema) -> list[str]:
        return sorted({arch.value for arch in result.architectures})


def construct_result(dependency_results: dict, file_path: str) -> dict[str, str]:
    """
    Returns a dict where keys are the architecture and values are the means of
    detection
    """
    result = {}
    result.update(dt.construct_result(dependency_results))
    result.update(kconfig.construct_result(dependency_results))
    result.update(elf.construct_result(file_path))
    result.update(metadata.construct_result(dependency_results))

    return result
