from __future__ import annotations

import binascii
import itertools
import logging
import zlib
from base64 import b64decode, b64encode
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from json import JSONDecodeError, loads
from multiprocessing import Manager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, List, Optional

from common_helper_files import get_binary_from_file, safe_rglob
from docker.errors import DockerException
from docker.types import Mount
from pydantic import BaseModel, Field
from requests.exceptions import ReadTimeout
from semver import Version

import config
from analysis.plugin import AnalysisPluginV0, Tag
from helperFunctions import magic
from helperFunctions.docker import run_docker_container
from helperFunctions.tag import TagColor
from helperFunctions.uid import create_uid
from unpacker.unpack_base import UnpackBase

if TYPE_CHECKING:
    from io import FileIO

PLUGIN_NAME = 'qemu_exec'
TIMEOUT_IN_SECONDS = 15
EXECUTABLE = 'executable'
EMPTY = '(no parameter)'
DOCKER_IMAGE = 'fact/qemu-exec:alpine-3.18'
QEMU_ERRORS = ['Unsupported syscall', 'Invalid ELF', 'uncaught target signal']
CONTAINER_TARGET_PATH = '/opt/firmware_root'

EXECUTABLE_TYPES = {'application/x-executable', 'application/x-pie-executable', 'application/x-sharedlib'}
FACT_EXTRACTION_FOLDER_NAME = 'fact_extracted'
ARCH_TO_BIN_DICT = OrderedDict(
    [
        ('aarch64', ['aarch64']),
        ('ARM', ['aarch64', 'arm', 'armeb']),
        ('MIPS32', ['mipsel', 'mips', 'mipsn32', 'mipsn32el']),
        ('MIPS64', ['mips64', 'mips64el']),
        ('MIPS', ['mipsel', 'mips', 'mips64', 'mips64el', 'mipsn32', 'mipsn32el']),
        ('80386', ['i386']),
        ('80486', ['x86_64', 'i386']),
        ('x86', ['x86_64', 'i386']),
        ('PowerPC', ['ppc', 'ppc64', 'ppc64le']),
        ('PPC', ['ppc', 'ppc64', 'ppc64le']),
        ('Renesas SH', ['sh4', 'sh4eb']),
    ]
)


class Unpacker(UnpackBase):
    @contextmanager
    def unpack_file(self, file_path: str):
        if not file_path or not Path(file_path).is_file():
            logging.error(f'could not unpack {file_path}: file not found')
            yield None
            return
        base_dir = config.backend.docker_mount_base_dir
        with TemporaryDirectory(prefix='FACT_plugin_qemu_exec', dir=base_dir) as extraction_dir:
            self.extract_files_from_file(file_path, extraction_dir)
            yield extraction_dir


class ParameterResult(BaseModel):
    parameters: str = Field(
        description=(
            'A CLI parameter or a comma-separated list of parameters (if multiple parameters produced the same output).'
        )
    )
    return_code: int
    stdout: str = Field(description='The STDOUT output of executing the file.')
    stderr: str = Field(description='The STDERR output of executing the file.')

    @classmethod
    def from_result(cls, parameter: str, result: dict):
        return cls(
            parameters=parameter,
            return_code=result['return_code'],
            stdout=result['stdout'],
            stderr=result['stderr'],
        )


class ArchResult(BaseModel):
    architecture: str = Field(description='QEMU system ISA that was used for trying to run the executable.')
    parameter_results: List[ParameterResult] = Field(
        description=(
            'The file is called with a list of different CLI parameters (no parameter, --help, etc.) and these '
            'are the individual results for each parameter (or combination of parameters if multiple different'
            'parameters produced the same output).'
        )
    )
    strace: Optional[str] = Field(
        None,
        description='A system call trace of executing the file (zlib compressed and base64 encoded to reduce size).',
    )
    error: Optional[str] = None

    @classmethod
    def from_arch_result(cls, arch: str, result_dict: dict) -> ArchResult:
        return cls(
            architecture=arch,
            strace=result_dict.get('strace'),
            error=result_dict.get('error'),
            parameter_results=[
                ParameterResult.from_result(parameter, parameter_results)
                for parameter, parameter_results in result_dict.items()
                if parameter not in {'strace', 'error'}
            ],
        )


class FileResult(BaseModel):
    is_executable: bool
    path: str = Field(description='File path of the included file in this file (obtained through unpacking).')
    uid: str
    extended_results: List[ArchResult] = Field(description='Individual results for all tested architectures')

    @classmethod
    def from_file_dict(cls, uid: str, file_result_dict: dict) -> FileResult:
        return cls(
            is_executable=file_result_dict[EXECUTABLE],
            path=file_result_dict['path'],
            uid=uid,
            extended_results=[
                ArchResult.from_arch_result(arch, arch_result_dict)
                for arch, arch_result_dict in file_result_dict['results'].items()
            ],
        )


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        parent_flag: bool = Field(
            description=(
                'Flag that is true if the parent file of this file should contain results for this file (since results '
                'are generated only for included files).'
            )
        )
        included_file_results: List[FileResult] = Field(
            description='Results for individual included files (unpacked from this file).'
        )

    def __init__(self, unpacker=None):
        super().__init__(
            metadata=self.MetaData(
                name=PLUGIN_NAME,
                description='test if included binaries can be executed with QEMU system and collect the output',
                dependencies=['file_type'],
                version=Version(1, 0, 0),
                Schema=self.Schema,
                mime_whitelist=[
                    *EXECUTABLE_TYPES,
                    'application/gzip',
                    'application/x-bzip2',
                    'application/x-cpio',
                    'application/x-xz',
                    'application/zip',
                    'filesystem/',
                ],
                timeout=600,
            ),
        )
        self.unpacker = Unpacker() if unpacker is None else unpacker

    def analyze(self, file_handle: FileIO, virtual_file_path: dict[str, list[str]], analyses: dict) -> Schema:
        del virtual_file_path
        if analyses['file_type'].mime in EXECUTABLE_TYPES:
            return self._process_included_binary()
        return self._process_container(file_handle.name)

    def _process_included_binary(self) -> Schema:
        # File should get analyzed when the parent file (container/file system/etc.) gets passed to this plugin
        # for this file we set only a flag, so that the data is dynamically loaded in the template
        return self.Schema(
            parent_flag=True,
            included_file_results=[],
        )

    def _process_container(self, file_path: str) -> Schema:
        with self.unpacker.unpack_file(file_path) as extraction_dir:
            return self.Schema(
                parent_flag=False,
                included_file_results=self._get_included_file_results(extraction_dir),
            )

    def _get_included_file_results(self, extraction_dir: str) -> list[FileResult]:
        extracted_files_dir = self.unpacker.get_extracted_files_dir(extraction_dir)
        if not extracted_files_dir.is_dir():
            return []
        root_path = _find_root_path(extracted_files_dir)
        file_list = _find_relevant_files(extracted_files_dir, root_path)
        if not file_list:
            return []
        result_dict = _process_included_files(file_list, root_path)
        return [FileResult.from_file_dict(uid, file_results) for uid, file_results in result_dict.items()]

    def summarize(self, result: Schema) -> list[str]:
        return [EXECUTABLE] if self._results_contain_executable_file(result) else []

    def get_tags(self, result: Schema, summary: list[str]) -> list[Tag]:
        del summary
        if self._results_contain_executable_file(result):
            return [
                Tag(
                    name=self.metadata.name,
                    value='QEMU executable',
                    propagate=True,
                    color=TagColor.BLUE,
                )
            ]
        return []

    @staticmethod
    def _results_contain_executable_file(results: Schema) -> bool:
        return any(file.is_executable for file in results.included_file_results)


def _find_relevant_files(extracted_files_dir: Path, root_path: Path) -> list[tuple[str, str]]:
    result = []
    for path in safe_rglob(extracted_files_dir):
        if path.is_file() and not path.is_symlink():
            mime = magic.from_file(path.absolute(), mime=True)
            if mime in EXECUTABLE_TYPES:
                file_type = magic.from_file(path.absolute(), mime=False)
                result.append((f'/{path.relative_to(root_path)}', file_type))
    return result


def _find_root_path(extracted_files_dir: Path) -> Path:
    root_path = extracted_files_dir
    if (root_path / FACT_EXTRACTION_FOLDER_NAME).is_dir():
        # if there is a 'fact_extracted' folder in the tmp dir: reset root path to that folder
        root_path /= FACT_EXTRACTION_FOLDER_NAME
    return root_path


def _process_included_files(file_list: list[tuple[str, str]], root_path: Path):
    with Manager() as manager:
        with ThreadPoolExecutor(max_workers=8) as executor:
            shared_dict = manager.dict()
            jobs = _run_analysis_jobs(executor, file_list, root_path, shared_dict)
            for future in jobs:  # wait for jobs to finish
                future.result()
        result_dict = shared_dict.copy()  # convert to a regular dict so we can use it after shutting down the manager
        for uid in shared_dict:
            result_dict[uid].update({EXECUTABLE: _valid_execution_in_results(result_dict[uid]['results'])})
        return result_dict


def _run_analysis_jobs(
    executor: ThreadPoolExecutor,
    file_list: list[tuple[str, str]],
    root_path: Path,
    results_dict: dict,
) -> list[Future]:
    jobs = []
    for file_path, full_type in file_list:
        uid = _get_uid(file_path, root_path)
        if uid not in results_dict:
            # file could be contained in the fo multiple times (but should be tested only once)
            for arch_suffix in _find_arch_suffixes(full_type):
                jobs.append(executor.submit(process_qemu_job, file_path, arch_suffix, root_path, results_dict, uid))
    return jobs


def _get_uid(file_path: str, root_path: Path) -> str:
    return create_uid(get_binary_from_file(str(root_path / file_path[1:])))


def _find_arch_suffixes(full_type):
    for arch_string in ARCH_TO_BIN_DICT:
        if arch_string in full_type:
            return ARCH_TO_BIN_DICT[arch_string]
    return []


def process_qemu_job(file_path: str, arch_suffix: str, root_path: Path, results_dict: dict, uid: str):
    result = check_qemu_executability(file_path, arch_suffix, root_path)
    if result:
        if uid in results_dict:
            tmp_dict = dict(results_dict[uid]['results'])
            tmp_dict.update({arch_suffix: result})
        else:
            tmp_dict = {arch_suffix: result}
        results_dict[uid] = {'path': file_path, 'results': tmp_dict}


def _valid_execution_in_results(results: dict):
    return any(
        _output_without_error_exists(results[arch][option])
        for arch in results
        if 'error' not in results[arch]
        for option in results[arch]
        if option not in ['strace', 'error']
    )


def _output_without_error_exists(docker_output: dict[str, str]) -> bool:
    try:
        return docker_output['stdout'] != '' and (docker_output['return_code'] == '0' or docker_output['stderr'] == '')
    except KeyError:
        return False


def check_qemu_executability(file_path: str, arch_suffix: str, root_path: Path) -> dict:
    result = get_docker_output(arch_suffix, file_path, root_path)
    if result and 'error' not in result:
        result = decode_output_values(result)
        if result_contains_qemu_errors(result):
            return {}
        result = process_docker_output(result)
    return result


def get_docker_output(arch_suffix: str, file_path: str, root_path: Path) -> dict:
    """
    :return: in the case of no error, the output will have the form
    {
        'parameter 1': {'stdout': <b64_str>, 'stderr': <b64_str>, 'return_code': <int>},
        'parameter 2': {...},
        '...',
        'strace': {'stdout': <b64_str>, 'stderr': <b64_str>, 'return_code': <int>},
    }
    in case of an error, there will be an entry 'error' instead of the entries stdout/stderr/return_code
    """
    command = f'{arch_suffix} {file_path}'
    try:
        result = run_docker_container(
            DOCKER_IMAGE,
            combine_stderr_stdout=True,
            timeout=TIMEOUT_IN_SECONDS,
            command=command,
            mounts=[
                Mount(CONTAINER_TARGET_PATH, str(root_path), type='bind'),
            ],
            logging_label='qemu_exec',
        )
        return loads(result.stdout)
    except ReadTimeout:
        return {'error': 'timeout'}
    except (DockerException, OSError):
        return {'error': 'process error'}
    except JSONDecodeError:
        return {'error': 'could not decode result'}


def process_docker_output(docker_output: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    process_strace_output(docker_output)
    replace_empty_strings(docker_output)
    merge_identical_results(docker_output)
    return docker_output


def decode_output_values(result_dict: dict[str, dict[str, str | int]]) -> dict[str, dict[str, str]]:
    result = {}
    for parameter in result_dict:
        for key, value in result_dict[parameter].items():
            if isinstance(value, str) and key != 'error':
                try:
                    str_value = b64decode(value.encode()).decode(errors='replace')
                except binascii.Error:
                    logging.warning(f'Error while decoding b64: {value}')
                    str_value = f'decoding error: {value}'
            else:
                str_value = str(value)
            result.setdefault(parameter, {})[key] = str_value
    return result


def _strace_output_exists(docker_output):
    return 'strace' in docker_output and 'stdout' in docker_output['strace'] and docker_output['strace']['stdout']


def process_strace_output(docker_output: dict):
    docker_output['strace'] = (
        # b64 + zip is still smaller than raw on average
        b64encode(zlib.compress(docker_output['strace']['stdout'].encode())).decode()
        if _strace_output_exists(docker_output)
        else None
    )


def result_contains_qemu_errors(docker_output: dict[str, dict[str, str]]) -> bool:
    return any(
        contains_docker_error(value) for parameter in docker_output for value in docker_output[parameter].values()
    )


def contains_docker_error(docker_output: str) -> bool:
    return any(error in docker_output for error in QEMU_ERRORS)


def replace_empty_strings(docker_output: dict[str, object]):
    for key in list(docker_output):
        if key == ' ':
            docker_output[EMPTY] = docker_output.pop(key)


def merge_identical_results(results: dict[str, dict[str, str]]):
    """
    if the results for different parameters (e.g. '-h' and '--help') are identical, merge them
    example input:  {'-h':         {'stdout': 'foo', 'stderr': '', 'return_code': 0},
                     '--help':     {'stdout': 'foo', 'stderr': '', 'return_code': 0}}
    example output: {'-h, --help': {'stdout': 'foo', 'stderr': '', 'return_code': 0}}
    """
    for parameter_1, parameter_2 in itertools.combinations(results, 2):
        if results[parameter_1] == results[parameter_2]:
            combined_key = f'{parameter_1}, {parameter_2}'
            results[combined_key] = results[parameter_1]
            results.pop(parameter_1)
            results.pop(parameter_2)
            merge_identical_results(results)
            break
