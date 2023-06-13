from __future__ import annotations

import json
import logging
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
    MIME_WHITELIST = ['application/x-dosexec']
    VERSION = '0.0.1'
    FILE = __file__

    def process_object(self, file_object: FileObject):
        file_object.processed_analysis.setdefault(self.NAME, {})

        type_result = file_object.processed_analysis['file_type'].get('result', {}).get('full', '')
        if 'EFI boot service driver' not in type_result:
            # only EFI modules are analyzed
            return file_object

        data = self._analyze_uefi_module(file_object.file_path)

        file_object.processed_analysis[self.NAME].update(data)
        file_object.processed_analysis[self.NAME]['summary'] = self._get_summary(data)
        return file_object

    def _analyze_uefi_module(self, path: str) -> dict[str, dict]:
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
            )
            data = json.loads(output_file.read_text())
            logging.warning(f'{data=}')
        return data

    def _get_summary(self, data: dict[str, dict]) -> list[str]:
        summary = set()
        for category, category_data in data.items():
            for rule_results in category_data.values():
                for variant_result in rule_results['variants'].values():
                    if variant_result['match']:
                        summary.add(category)
                        continue
        return sorted(summary)
