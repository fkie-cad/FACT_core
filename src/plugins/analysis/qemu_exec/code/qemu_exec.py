import itertools
import logging
from collections import OrderedDict
from multiprocessing import Manager, Pool
from pathlib import Path
from re import findall
from tempfile import TemporaryDirectory
from typing import Dict, List, Optional, Tuple
from zlib import compress

from analysis.PluginBase import AnalysisBasePlugin
from common_helper_files import get_binary_from_file
from common_helper_process import execute_shell_command_get_return_code
from fact_helper_file import get_file_type_from_path
from helperFunctions.tag import TagColor
from helperFunctions.uid import create_uid
from objects.file import FileObject
from storage.binary_service import BinaryServiceDbInterface
from unpacker.unpackBase import UnpackBase

TIMEOUT = 5
EXECUTABLE = 'executable'
EMPTY = '(no parameter)'
DOCKER_IMAGE = 'fact/qemu:latest'


class Unpacker(UnpackBase):
    def unpack_fo(self, file_object: FileObject) -> Optional[TemporaryDirectory]:
        file_path = file_object.file_path if file_object.file_path else self._get_file_path_from_db(file_object.get_uid())
        if not file_path or not Path(file_path).is_file():
            logging.error('could not unpack {}: file path not found'.format(file_object.get_uid()))
            return None

        extraction_dir = TemporaryDirectory(prefix='FACT_plugin_qemu_exec')
        self.extract_files_from_file(file_path, extraction_dir.name)
        return extraction_dir

    def _get_file_path_from_db(self, uid):
        binary_service = BinaryServiceDbInterface(config=self.config)
        try:
            path = binary_service.get_file_name_and_path(uid)['file_path']
            return path
        except (KeyError, TypeError):
            return None
        finally:
            binary_service.shutdown()


class AnalysisPlugin(AnalysisBasePlugin):

    NAME = 'qemu_exec'
    DESCRIPTION = 'test binaries for executability in QEMU and display help if available'
    VERSION = '0.4.1'
    DEPENDENCIES = ['file_type']
    FILE_TYPES = ['application/x-executable']

    FACT_EXTRACTION_FOLDER_NAME = 'fact_extracted'

    arch_to_bin_dict = OrderedDict([
        ('aarch64', ['aarch64']),
        ('ARM', ['aarch64', 'arm', 'armeb']),

        ('MIPS32', ['mipsel', 'mips', 'mipsn32', 'mipsn32el']),
        ('MIPS64', ['mips64', 'mips64el']),
        ('MIPS', ['mipsel', 'mips', 'mips64', 'mips64el', 'mipsn32', 'mipsn32el']),

        ('80386', ['i386']),
        ('80486', ['x86_64', 'i386']),
        ('x86', ['x86_64', 'i386']),

        ('PowerPC', ['ppc', 'ppc64', 'ppc64abi32', 'ppc64le']),
        ('PPC', ['ppc', 'ppc64', 'ppc64abi32', 'ppc64le']),

        ('Renesas SH', ['sh4', 'sh4eb']),
    ])

    root_path = None

    def __init__(self, plugin_administrator, config=None, recursive=True, unpacker=None):
        self.unpacker = Unpacker(config) if unpacker is None else unpacker
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__, timeout=600)

    def process_object(self, file_object: FileObject) -> FileObject:
        if not docker_is_running():
            logging.error('could not process object: docker daemon not running')
            return file_object

        if self.NAME not in file_object.processed_analysis:
            file_object.processed_analysis[self.NAME] = {}
        file_object.processed_analysis[self.NAME]['summary'] = []

        if file_object.processed_analysis['file_type']['mime'] in self.FILE_TYPES:
            return self._process_included_binary(file_object)
        else:
            return self._process_container(file_object)

    def _process_included_binary(self, file_object: FileObject) -> FileObject:
        # File will get analyzed in the parent container
        file_object.processed_analysis[self.NAME]['parent_flag'] = True
        return file_object

    def _process_container(self, file_object: FileObject) -> FileObject:
        if len(file_object.files_included) == 0:
            return file_object

        tmp_dir = self.unpacker.unpack_fo(file_object)

        if tmp_dir:
            try:
                self.root_path = self._find_root_path(tmp_dir)
                file_list = self._find_relevant_files(tmp_dir)
                if file_list:
                    file_object.processed_analysis[self.NAME]['files'] = {}
                    self._process_included_files(file_list, file_object)
            finally:
                tmp_dir.cleanup()

        return file_object

    def _find_relevant_files(self, tmp_dir: TemporaryDirectory):
        result = []
        for f in Path(tmp_dir.name).glob('**/*'):
            if f.is_file() and not f.is_symlink():
                file_type = get_file_type_from_path(f.absolute())
                if self._has_relevant_type(file_type):
                    result.append(('/{}'.format(f.relative_to(Path(self.root_path))), file_type['full']))
        return result

    def _find_root_path(self, tmp_dir: TemporaryDirectory) -> Path:
        root_path = Path(tmp_dir.name)
        if (root_path / self.FACT_EXTRACTION_FOLDER_NAME).is_dir():
            # if there a 'fact_extracted' folder in the tmp dir: reset root path to that folder
            root_path /= self.FACT_EXTRACTION_FOLDER_NAME
        return root_path

    def _has_relevant_type(self, file_type: dict):
        if file_type is not None and file_type['mime'] in self.FILE_TYPES:
            return True
        return False

    def _process_included_files(self, file_list, file_object):
        manager = Manager()
        pool = Pool(processes=8)
        results_dict = manager.dict()

        jobs = self._create_analysis_jobs(file_list, file_object, results_dict)
        pool.starmap(process_qemu_job, jobs, chunksize=1)
        self._enter_results(dict(results_dict), file_object)
        self._add_tag(file_object)

    def _create_analysis_jobs(self, file_list: List[Tuple[str, str]], file_object: FileObject, results_dict: dict) -> List[tuple]:
        jobs = []
        for file_path, full_type in file_list:
            uid = self._get_uid(file_path, self.root_path)
            if uid not in file_object.processed_analysis[self.NAME]['files']:
                # file could be contained in the fo multiple times (but should be tested only once)
                qemu_arch_suffixes = self._find_arch_suffixes(full_type)
                jobs.extend(
                    [(file_path, arch_suffix, self.root_path, results_dict, uid) for arch_suffix in qemu_arch_suffixes])
        return jobs

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
            tmp[uid]['executable'] = self._valid_execution_in_results(tmp[uid]['results'])
        file_object.processed_analysis['qemu_exec']['summary'] = self._get_summary(tmp)

    @staticmethod
    def _valid_execution_in_results(results: dict):
        return any(
            results[arch][option]['stdout'] != '' and (results[arch][option]['return_code'] == '0' or results[arch][option]['stderr'] == '')
            for arch in results
            for option in results[arch]
            if option != 'strace'
        )

    def _add_tag(self, file_object: FileObject):
        result = file_object.processed_analysis[self.NAME]['files']
        if any(result[uid]['executable'] for uid in result):
            self.add_analysis_tag(
                file_object=file_object,
                tag_name=self.NAME,
                value='QEMU executable',
                color=TagColor.BLUE,
                propagate=True
            )

    @staticmethod
    def _get_summary(results: dict):
        if any(results[uid][EXECUTABLE] for uid in results):
            return [EXECUTABLE]
        return []


def process_qemu_job(file_path: str, arch_suffix: str, root_path: Path, results_dict: dict, uid: str):
    result = test_qemu_executability(file_path, arch_suffix, root_path)
    if result:
        if uid in results_dict:
            tmp_dict = dict(results_dict[uid]['results'])
            tmp_dict.update({arch_suffix: result})
        else:
            tmp_dict = {arch_suffix: result}
        results_dict[uid] = {
            'path': file_path,
            'results': tmp_dict
        }


def test_qemu_executability(file_path: str, arch_suffix: str, root_path: Path) -> dict:
    result = {}

    response = get_docker_output(arch_suffix, file_path, root_path)
    if response:
        result = parse_docker_output(response)

    return result


def get_docker_output(arch_suffix: str, file_path: str, root_path: Path) -> Optional[str]:
    call = 'docker run --rm --net=none -v {}:/opt/firmware_root {} {} {}'.format(
        root_path, DOCKER_IMAGE, arch_suffix, file_path)
    response, return_code = execute_shell_command_get_return_code(call, timeout=TIMEOUT)
    if return_code != 0:
        if 'timed out' in response:
            logging.warning('encountered timeout while trying to run docker container')
        else:
            logging.warning('encountered process error while trying to run docker container')
        return None
    return response


def parse_docker_output(docker_output: str) -> dict:
    result = parse_docker_output_options(docker_output)
    merge_similar_entries(result)
    result.update(parse_docker_output_strace(docker_output))
    return result


def merge_similar_entries(results_dict: Dict[str, Dict[str, str]]):
    for option_1, option_2 in itertools.combinations(results_dict, 2):
        if results_dict[option_1] == results_dict[option_2]:
            combined_key = '{}, {}'.format(option_1, option_2)
            results_dict[combined_key] = results_dict[option_1]
            results_dict.pop(option_1)
            results_dict.pop(option_2)
            merge_similar_entries(results_dict)
            break


def parse_docker_output_options(docker_output: str) -> Dict[str, Dict[str, str]]:
    options_regex = '(?s)§#§option§#§((?:(?!§#§).)+)§#§\n' \
                    '§#§stdout§#§((?:(?!§#§).)*)§#§\n' \
                    '§#§stderr§#§((?:(?!§#§).)*)§#§\n' \
                    '§#§return_code§#§((?:(?!§#§).)*)§#§'

    result = {
        option if option != ' ' else EMPTY: {
            'stdout': stdout,
            'stderr': stderr,
            'return_code': return_code,
        }
        for option, stdout, stderr, return_code in findall(options_regex, docker_output)
        if not contains_docker_error(stderr) and not stderr == stdout == ''
    }

    return result


def parse_docker_output_strace(docker_output: str) -> dict:
    strace_regex = '(?s)§#§strace§#§\n' \
                   '§#§stdout§#§((?:(?!§#§).)*)§#§\n' \
                   '§#§stderr§#§((?:(?!§#§).)*)§#§'

    return {
        'strace': compress(output.encode())
        for _, output in findall(strace_regex, docker_output)
        if not contains_docker_error(output) and not output == ''
    }


def contains_docker_error(docker_output: str) -> bool:
    error_messages = ['Unsupported syscall', 'Invalid ELF', 'uncaught target signal']
    return any(e in docker_output for e in error_messages)


def docker_is_running() -> bool:
    _, return_code = execute_shell_command_get_return_code('pgrep dockerd')
    return return_code == 0
