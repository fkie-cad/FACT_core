from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.docker import run_docker_container

from docker.types import Mount

if TYPE_CHECKING:
    from objects.file import FileObject

DOCKER_IMAGE = 'fact/uefi'


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'uefi'
    DESCRIPTION = 'find vulnerabilities in UEFI modules using the tool FwHunt'
    DEPENDENCIES = ['file_type']
    MIME_WHITELIST = ['application/x-dosexec', 'firmware/uefi']
    VERSION = '0.0.1'
    FILE = __file__

    def process_object(self, file_object: FileObject):
        file_object.processed_analysis.setdefault(self.NAME, {})

        mime = file_object.processed_analysis['file_type'].get('result', {}).get('mime', '')
        type_result = file_object.processed_analysis['file_type'].get('result', {}).get('full', '')
        if _is_no_uefi_module(mime, type_result):
            # only EFI modules are analyzed, not regular PE files
            return file_object

        data = self._analyze_uefi_module(file_object.file_path, _get_analysis_mode(mime))

        file_object.processed_analysis[self.NAME].update(data)
        file_object.processed_analysis[self.NAME]['summary'] = self._get_summary(data)
        return file_object

    def _analyze_uefi_module(self, path: str, mode: str) -> dict[str, dict]:
        with TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / 'output.json'
            output_file.write_text('{}')
            run_docker_container(
                DOCKER_IMAGE,
                combine_stderr_stdout=True,
                timeout=self.TIMEOUT,
                mounts=[
                    Mount('/input/file', path, type='bind'),
                    Mount('/output/file', str(output_file), type='bind'),
                ],
                environment={'UEFI_ANALYSIS_MODE': mode},
            )
            return json.loads(output_file.read_text())

    def _get_summary(self, data: dict[str, dict]) -> list[str]:
        summary = set()
        for category, category_data in data.items():
            for rule_results in category_data.values():
                for variant_result in rule_results['variants'].values():
                    if variant_result['match']:
                        summary.add(category)
                        continue
        return sorted(summary)


def _is_no_uefi_module(mime: str, type_result: str) -> bool:
    return mime == 'application/x-dosexec' and 'EFI boot service driver' not in type_result


def _get_analysis_mode(mime: str) -> str:
    return 'firmware' if mime == 'firmware/uefi' else 'module'
