from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Union

from docker.types import Mount
from pydantic import BaseModel, Field
from semver import Version

from analysis.plugin import AnalysisPluginV0
from helperFunctions.docker import run_docker_container

if TYPE_CHECKING:
    from io import FileIO

DOCKER_IMAGE = 'ipc'


class FunctionCall(BaseModel):
    name: str = Field(
        # Refer to sink_function_names in ../docker/ipc_analyzer/ipy_analyzer.py for a list of supported functions
        description='The name of the function.',
    )
    target: Union[str, int] = Field(
        description=(
            'The first argument of the function call. '
            'For all supported functions, this is either a pathname or a file descriptor.'
        ),
    )
    arguments: List[Any] = Field(
        description=(
            'The remaining arguments of the function call. Arguments of type `char*` are rendered as strings. '
            'Arguments of type `char**` are rendered as array of strings. Integer arrays are rendered as such. '
            'Everything else is rendered as integer.'
        )
    )


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        calls: List[FunctionCall] = Field(description='An array of IPC function calls.')

    def __init__(self):
        metadata = self.MetaData(
            name='ipc_analyzer',
            dependencies=['file_type'],
            description='Inter-Process Communication Analysis',
            mime_whitelist=[
                'application/x-executable',
                'application/x-object',
                'application/x-pie-executable',
                'application/x-sharedlib',
            ],
            timeout=600,
            version=Version(1, 0, 0),
            Schema=self.Schema,
        )
        super().__init__(metadata=metadata)

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel]) -> Schema:
        del virtual_file_path, analyses
        output = self._run_ipc_analyzer_in_docker(file_handle)
        # output structure: { 'target': [{'type': 'type', 'arguments': [...]}, ...], ...}
        # we need to restructure this a bit so it lines up with the Schema
        calls = [
            {'target': target, 'name': call_dict['type'], 'arguments': call_dict['arguments']}
            for target, call_list in output['ipcCalls'].items()
            for call_dict in call_list
        ]
        return self.Schema.model_validate({'calls': calls})

    def _run_ipc_analyzer_in_docker(self, file_handle: FileIO) -> dict:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(file_handle.name).absolute()
            folder = Path(tmp_dir) / 'results'
            mount = f'/input/{path.name}'
            if not folder.exists():
                folder.mkdir()
            output = folder / f'{path.name}.json'
            output.write_text(json.dumps({'ipcCalls': {}}))
            run_docker_container(
                DOCKER_IMAGE,
                combine_stderr_stdout=True,
                timeout=self.TIMEOUT,
                command=f'{mount} /results/',
                mounts=[
                    Mount('/results/', str(folder.resolve()), type='bind'),
                    Mount(mount, str(path), type='bind'),
                ],
            )
            return json.loads(output.read_text())

    def summarize(self, result: Schema) -> list[str]:
        return sorted({call.name for call in result.calls})
