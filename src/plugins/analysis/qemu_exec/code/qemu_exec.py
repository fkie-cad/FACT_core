from __future__ import annotations

import binascii
import itertools
import logging
import zlib
from base64 import b64decode, b64encode
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from json import JSONDecodeError, loads
from multiprocessing import Manager
from pathlib import Path
from tempfile import TemporaryDirectory

from common_helper_files import get_binary_from_file, safe_rglob
from docker.errors import DockerException
from docker.types import Mount
from fact_helper_file import get_file_type_from_path
from requests.exceptions import ReadTimeout

from analysis.PluginBase import AnalysisBasePlugin
from config import cfg, configparser_cfg
from helperFunctions.docker import run_docker_container
from helperFunctions.tag import TagColor
from helperFunctions.uid import create_uid
from objects.file import FileObject
from storage.fsorganizer import FSOrganizer
from unpacker.unpack_base import UnpackBase

TIMEOUT_IN_SECONDS = 15
EXECUTABLE = 'executable'
EMPTY = '(no parameter)'
DOCKER_IMAGE = 'fact/qemu-exec:alpine-3.14'
QEMU_ERRORS = ['Unsupported syscall', 'Invalid ELF', 'uncaught target signal']
CONTAINER_TARGET_PATH = '/opt/firmware_root'


class Unpacker(UnpackBase):
    def __init__(self, worker_id=None):
        super().__init__(worker_id=worker_id)
        self.fs_organizer = FSOrganizer()

    def unpack_fo(self, file_object: FileObject) -> TemporaryDirectory | None:
        file_path = file_object.file_path if file_object.file_path else self._get_path_from_fo(file_object)
        if not file_path or not Path(file_path).is_file():
            logging.error(f'could not unpack {file_object.uid}: file path not found')
            return None

        extraction_dir = TemporaryDirectory(prefix='FACT_plugin_qemu_exec', dir=cfg.data_storage.docker_mount_base_dir)
        self.extract_files_from_file(file_path, extraction_dir.name)
        return extraction_dir

    def _get_path_from_fo(self, file_object: FileObject) -> str:
        return self.fs_organizer.generate_path(file_object)


class AnalysisPlugin(AnalysisBasePlugin):

    NAME = 'qemu_exec'
    DESCRIPTION = 'test binaries for executability in QEMU and display help if available'
    VERSION = '0.5.2'
    DEPENDENCIES = ['file_type']
    FILE = __file__

    FILE_TYPES = ['application/x-executable', 'application/x-pie-executable', 'application/x-sharedlib']
    FACT_EXTRACTION_FOLDER_NAME = 'fact_extracted'

    arch_to_bin_dict = OrderedDict(
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

    root_path = None

    def __init__(self, *args, unpacker=None, **kwargs):
        self.unpacker = Unpacker(configparser_cfg) if unpacker is None else unpacker
        super().__init__(*args, **kwargs)

    def process_object(self, file_object: FileObject) -> FileObject:
        if self.NAME not in file_object.processed_analysis:
            file_object.processed_analysis[self.NAME] = {}
        file_object.processed_analysis[self.NAME]['summary'] = []

        if file_object.processed_analysis['file_type']['mime'] in self.FILE_TYPES:
            return self._process_included_binary(file_object)
        return self._process_container(file_object)

    def _process_included_binary(self, file_object: FileObject) -> FileObject:
        # File will get analyzed in the parent container
        file_object.processed_analysis[self.NAME]['parent_flag'] = True
        return file_object

    def _process_container(self, file_object: FileObject) -> FileObject:
        if not file_object.files_included:
            return file_object

        tmp_dir = self.unpacker.unpack_fo(file_object)
        extracted_files_dir = self.unpacker.get_extracted_files_dir(tmp_dir.name)

        if extracted_files_dir.is_dir():
            try:
                self.root_path = self._find_root_path(extracted_files_dir)
                file_list = self._find_relevant_files(extracted_files_dir)
                if file_list:
                    file_object.processed_analysis[self.NAME]['files'] = {}
                    self._process_included_files(file_list, file_object)
            finally:
                tmp_dir.cleanup()

        return file_object

    def _find_relevant_files(self, extracted_files_dir: Path):
        result = []
        for path in safe_rglob(extracted_files_dir):
            if path.is_file() and not path.is_symlink():
                file_type = get_file_type_from_path(path.absolute())
                if self._has_relevant_type(file_type):
                    result.append((f'/{path.relative_to(Path(self.root_path))}', file_type['full']))
        return result

    def _find_root_path(self, extracted_files_dir: Path) -> Path:
        root_path = extracted_files_dir
        if (root_path / self.FACT_EXTRACTION_FOLDER_NAME).is_dir():
            # if there is a 'fact_extracted' folder in the tmp dir: reset root path to that folder
            root_path /= self.FACT_EXTRACTION_FOLDER_NAME
        return root_path

    def _has_relevant_type(self, file_type: dict):
        if file_type is not None and file_type['mime'] in self.FILE_TYPES:
            return True
        return False

    def _process_included_files(self, file_list, file_object):
        manager = Manager()
        executor = ThreadPoolExecutor(max_workers=8)
        results_dict = manager.dict()

        jobs = self._run_analysis_jobs(executor, file_list, file_object, results_dict)
        for future in jobs:  # wait for jobs to finish
            future.result()
        executor.shutdown(wait=False)
        self._enter_results(dict(results_dict), file_object)
        self._add_tag(file_object)

    def _run_analysis_jobs(
        self,
        executor: ThreadPoolExecutor,
        file_list: list[tuple[str, str]],
        file_object: FileObject,
        results_dict: dict,
    ) -> list[Future]:
        jobs = []
        for file_path, full_type in file_list:
            uid = self._get_uid(file_path, self.root_path)
            if self._analysis_not_already_completed(file_object, uid):
                for arch_suffix in self._find_arch_suffixes(full_type):
                    jobs.append(
                        executor.submit(process_qemu_job, file_path, arch_suffix, self.root_path, results_dict, uid)
                    )
        return jobs

    def _analysis_not_already_completed(self, file_object, uid):
        # file could be contained in the fo multiple times (but should be tested only once)
        return uid not in file_object.processed_analysis[self.NAME]['files']

    @staticmethod
    def _get_uid(file_path, root_path: Path):
        return create_uid(get_binary_from_file(str(root_path / file_path[1:])))

    def _find_arch_suffixes(self, full_type):
        for arch_string in self.arch_to_bin_dict:
            if arch_string in full_type:
                return self.arch_to_bin_dict[arch_string]
        return []

    def _enter_results(self, results, file_object):
        tmp = file_object.processed_analysis[self.NAME]['files'] = results
        for uid in tmp:
            tmp[uid][EXECUTABLE] = _valid_execution_in_results(tmp[uid]['results'])
        file_object.processed_analysis['qemu_exec']['summary'] = self._get_summary(tmp)

    def _add_tag(self, file_object: FileObject):
        result = file_object.processed_analysis[self.NAME]['files']
        if any(result[uid][EXECUTABLE] for uid in result):
            self.add_analysis_tag(
                file_object=file_object,
                tag_name=self.NAME,
                value='QEMU executable',
                color=TagColor.BLUE,
                propagate=True,
            )

    @staticmethod
    def _get_summary(results: dict):
        if any(results[uid][EXECUTABLE] for uid in results):
            return [EXECUTABLE]
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
    '''
    :return: in the case of no error, the output will have the form
    {
        'parameter 1': {'stdout': <b64_str>, 'stderr': <b64_str>, 'return_code': <int>},
        'parameter 2': {...},
        '...',
        'strace': {'stdout': <b64_str>, 'stderr': <b64_str>, 'return_code': <int>},
    }
    in case of an error, there will be an entry 'error' instead of the entries stdout/stderr/return_code
    '''
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
        else {}
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
    '''
    if the results for different parameters (e.g. '-h' and '--help') are identical, merge them
    example input:  {'-h':         {'stdout': 'foo', 'stderr': '', 'return_code': 0},
                     '--help':     {'stdout': 'foo', 'stderr': '', 'return_code': 0}}
    example output: {'-h, --help': {'stdout': 'foo', 'stderr': '', 'return_code': 0}}
    '''
    for parameter_1, parameter_2 in itertools.combinations(results, 2):
        if results[parameter_1] == results[parameter_2]:
            combined_key = f'{parameter_1}, {parameter_2}'
            results[combined_key] = results[parameter_1]
            results.pop(parameter_1)
            results.pop(parameter_2)
            merge_identical_results(results)
            break
