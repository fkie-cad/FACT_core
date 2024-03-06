from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from docker.types import Mount

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.docker import run_docker_container

if TYPE_CHECKING:
    from objects.file import FileObject

DOCKER_IMAGE = 'ipc'


class AnalysisPlugin(AnalysisBasePlugin):
    """
    Inter-Process Communication Analysis
    """

    NAME = 'ipc_analyzer'
    DESCRIPTION = 'Inter-Process Communication Analysis'
    VERSION = '0.1.1'
    FILE = __file__

    MIME_WHITELIST = [  # noqa: RUF012
        'application/x-executable',
        'application/x-object',
        'application/x-sharedlib',
    ]
    DEPENDENCIES = ['file_type']  # noqa: RUF012
    TIMEOUT = 600  # 10 minutes

    def _run_ipc_analyzer_in_docker(self, file_object: FileObject) -> dict:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir) / 'results'
            mount = f'/input/{file_object.file_name}'
            if not folder.exists():
                folder.mkdir()
            output = folder / f'{file_object.file_name}.json'
            output.write_text(json.dumps({'ipcCalls': {}}))
            run_docker_container(
                DOCKER_IMAGE,
                combine_stderr_stdout=True,
                timeout=self.TIMEOUT,
                command=f'{mount} /results/',
                mounts=[
                    Mount('/results/', str(folder.resolve()), type='bind'),
                    Mount(mount, file_object.file_path, type='bind'),
                ],
            )
            return json.loads(output.read_text())

    def _do_full_analysis(self, file_object: FileObject) -> FileObject:
        output = self._run_ipc_analyzer_in_docker(file_object)
        file_object.processed_analysis[self.NAME] = {
            'full': output,
            'summary': self._create_summary(output['ipcCalls']),
        }
        return file_object

    def process_object(self, file_object: FileObject) -> FileObject:
        """
        This function handles only ELF executables. Otherwise, it returns an empty dictionary.
        It calls the ipc docker container.
        """
        return self._do_full_analysis(file_object)

    @staticmethod
    def _create_summary(output: dict) -> list[str]:
        # output structure: { 'target': [{'type': 'type', 'arguments': [...]}, ...], ...}
        summary = {entry['type'] for result_list in output.values() for entry in result_list}
        return sorted(summary)
