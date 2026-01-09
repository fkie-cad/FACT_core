from __future__ import annotations

from json import JSONDecodeError, loads
from typing import TYPE_CHECKING

from docker.errors import DockerException
from docker.types import Mount
from pydantic import BaseModel
from semver import Version

from analysis.plugin import AnalysisPluginV0
from helperFunctions.docker import run_docker_container

if TYPE_CHECKING:
    from io import FileIO

DOCKER_IMAGE = 'input-vectors:latest'
TIMEOUT_IN_SECONDS = 120
CONTAINER_TARGET_PATH = '/tmp/input'


class InputVectorsAnalysisError(Exception):
    pass


class InputVector(BaseModel):
    name: str
    xrefs: list[str]
    count: int | None = None


class InputVectors(BaseModel):
    bus_usb: list[InputVector] | None = None
    environment: list[InputVector] | None = None
    file: list[InputVector] | None = None
    ipc: list[InputVector] | None = None
    network: list[InputVector] | None = None
    random: list[InputVector] | None = None
    shell: list[InputVector] | None = None
    signal: list[InputVector] | None = None
    stdin: list[InputVector] | None = None
    time: list[InputVector] | None = None


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        inputs: InputVectors
        configs: list[str]
        url_paths: list[str]
        domains: list[str]

    def __init__(self):
        super().__init__(
            metadata=self.MetaData(
                name='input_vectors',
                description='Determines possible input vectors of an ELF executable like stdin, network, or syscalls.',
                version=Version(1, 0, 0),
                Schema=self.Schema,
                mime_whitelist=[
                    'application/x-executable',
                    'application/x-object',
                    'application/x-sharedlib',
                    'application/x-pie-executable',
                ],
                timeout=TIMEOUT_IN_SECONDS,
            ),
        )

    def analyze(self, file_handle: FileIO, virtual_file_path: dict[str, list[str]], analyses: dict) -> Schema:
        del virtual_file_path, analyses
        analysis_data = self._run_docker(file_handle)
        return self.Schema(
            inputs=analysis_data['inputs'],
            configs=analysis_data['configs'],
            url_paths=analysis_data['url_paths'],
            domains=analysis_data['domains'],
        )

    def _run_docker(self, file_handle: FileIO) -> dict:
        try:
            result = run_docker_container(
                DOCKER_IMAGE,
                # We explicitly don't want stderr to ignore "Cannot analyse at [...]"
                combine_stderr_stdout=False,
                logging_label=self.metadata.name,
                timeout=TIMEOUT_IN_SECONDS - 10,
                command=CONTAINER_TARGET_PATH,
                mounts=[
                    Mount(CONTAINER_TARGET_PATH, file_handle.name, type='bind', read_only=True),
                ],
            )
            analysis_data = loads(result.stdout)['full']
        except (DockerException, OSError, KeyError) as err:
            raise InputVectorsAnalysisError('Analysis issues. It might not be complete.') from err
        except JSONDecodeError as err:
            raise InputVectorsAnalysisError('Could not decode JSON output') from err
        return analysis_data

    def summarize(self, result: Schema) -> list:
        summary = []
        for key, value in result.inputs.model_dump().items():
            if key == 'inputs':
                for input_class, input_vector in value.items():
                    if input_vector:
                        summary.append(input_class)
            elif value:
                summary.append(key)
        return summary
