# pylint: disable=protected-access, no-self-use
import os
from contextlib import suppress
from pathlib import Path
from test.common_helper import create_test_firmware
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from unittest import TestCase
from zlib import decompress

import pytest
from common_helper_files import get_dir_of_file
from helperFunctions.config import get_config_for_testing
from helperFunctions.fileSystem import get_test_data_dir

from ..code import qemu_exec

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data/test_tmp_dir')
TEST_DATA_DIR_2 = os.path.join(get_dir_of_file(__file__), 'data/test_tmp_dir_2')


class MockTmpDir:
    def __init__(self, name):
        self.name = name

    def cleanup(self):
        pass


class MockUnpacker:
    tmp_dir = None

    def unpack_fo(self, _):
        return self.tmp_dir

    def set_tmp_dir(self, tmp_dir):
        self.tmp_dir = tmp_dir


@pytest.fixture
def execute_shell_fails(monkeypatch):
    def mock_execute_shell(*_, **__):
        return '', 1
    monkeypatch.setattr(qemu_exec, 'execute_shell_command_get_return_code', mock_execute_shell)


@pytest.fixture
def execute_shell_timeout(monkeypatch):
    def mock_execute_shell(call, **_):
        if call == 'pgrep dockerd':
            return '', 0
        return 'timed out', 1
    monkeypatch.setattr(qemu_exec, 'execute_shell_command_get_return_code', mock_execute_shell)


class TestPluginQemuExec(AnalysisPluginTest):

    PLUGIN_NAME = 'qemu_exec'
    docker_test_output = '§#§option§#§--version§#§\n' \
                         '§#§stdout§#§Unknown option. Usage: ./hello_world --help§#§\n' \
                         '§#§stderr§#§§#§\n' \
                         '§#§return_code§#§1§#§\n' \
                         '§#§option§#§ §#§\n' \
                         '§#§stdout§#§Hello World§#§\n' \
                         '§#§stderr§#§§#§\n' \
                         '§#§return_code§#§0§#§\n' \
                         '§#§strace§#§\n' \
                         '§#§stdout§#§Hello World§#§\n' \
                         '§#§stderr§#§38 uname(0x7ffffb38) = 0\n38 brk(NULL) = 0x004a2000\n38 brk(0x004a2cc8) = 0x004a2cc8§#§'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.mock_unpacker = MockUnpacker()
        self.analysis_plugin = qemu_exec.AnalysisPlugin(self, config=config, unpacker=self.mock_unpacker)

    def test_has_relevant_type(self):
        assert self.analysis_plugin._has_relevant_type(None) is False
        assert self.analysis_plugin._has_relevant_type({'mime': 'foo'}) is False
        assert self.analysis_plugin._has_relevant_type({'mime': 'application/x-executable'}) is True

    def test_find_relevant_files(self):
        tmp_dir = MockTmpDir(TEST_DATA_DIR)
        self.analysis_plugin.root_path = tmp_dir.name
        self.analysis_plugin.unpacker.set_tmp_dir(tmp_dir)
        result = sorted(self.analysis_plugin._find_relevant_files(tmp_dir))
        assert len(result) == 4

        path_list, mime_types = list(zip(*result))
        for path in ['/lib/ld.so.1', '/lib/libc.so.6', '/test_mips_static', '/usr/bin/test_mips']:
            assert path in path_list
        assert all('MIPS' in mime for mime in mime_types)

    def test_get_docker_output__static(self):
        result = qemu_exec.get_docker_output('mips', '/test_mips_static', TEST_DATA_DIR)
        assert 'Hello World' in result

    def test_get_docker_output__dynamic(self):
        result = qemu_exec.get_docker_output('mips', '/usr/bin/test_mips', TEST_DATA_DIR)
        assert 'Hello World' in result

    def test_get_docker_output__wrong_arch(self):
        result = qemu_exec.get_docker_output('i386', '/test_mips_static', TEST_DATA_DIR)
        assert 'Invalid ELF image' in result

    @pytest.mark.usefixtures('execute_shell_timeout')
    def test_get_docker_output__timeout(self):
        result = qemu_exec.get_docker_output('mips', '/test_mips_static', TEST_DATA_DIR)
        assert result is None

    def test_test_qemu_executability(self):
        self.analysis_plugin.OPTIONS = ['-h']

        result = qemu_exec.test_qemu_executability('/test_mips_static', 'mips', TEST_DATA_DIR)
        assert any('--help' in option for option in result)
        option = [option for option in result if '--help' in option][0]
        assert result[option]['stdout'] == 'Hello World'
        assert result[option]['stderr'] == ''
        assert result[option]['return_code'] == '0'

        result = qemu_exec.test_qemu_executability('/test_mips_static', 'i386', TEST_DATA_DIR)
        assert result == {}

    def test_find_arch_suffixes(self):
        mime_str = 'ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked'
        result = self.analysis_plugin._find_arch_suffixes(mime_str)
        assert result != []
        # the more specific architecture variants should be checked first
        assert result == self.analysis_plugin.arch_to_bin_dict['MIPS32']
        assert result != self.analysis_plugin.arch_to_bin_dict['MIPS']

    def test_find_arch_suffixes__unknown_arch(self):
        mime_str = 'foo'
        result = self.analysis_plugin._find_arch_suffixes(mime_str)
        assert result == []

    def test_process_included_files(self):
        self.analysis_plugin.OPTIONS = ['-h']
        test_fw = create_test_firmware()
        test_uid = '6b4142fa7e0a35ff6d10e18654be8ac5b778c3b5e2d3d345d1a01c2bcbd51d33_676340'
        test_fw.processed_analysis[self.analysis_plugin.NAME] = result = {'files': {}}
        file_list = [('/test_mips_static', '-MIPS32-')]

        self.analysis_plugin.root_path = Path(TEST_DATA_DIR)
        self.analysis_plugin._process_included_files(file_list, test_fw)
        assert result is not None
        assert 'files' in result
        assert test_uid in result['files']
        assert result['files'][test_uid]['executable'] is True

    def test_process_object(self):
        self.analysis_plugin.OPTIONS = ['-h']
        test_fw = self._set_up_fw_for_process_object()

        self.analysis_plugin.process_object(test_fw)
        result = test_fw.processed_analysis[self.analysis_plugin.NAME]
        assert 'files' in result
        assert len(result['files']) == 4
        assert any(result['files'][uid]['executable'] for uid in result['files'])

    def test_process_object__with_extracted_folder(self):
        self.analysis_plugin.OPTIONS = ['-h']
        test_fw = self._set_up_fw_for_process_object(path=TEST_DATA_DIR_2)
        test_file_uid = '68bbef24a7083ca2f5dc93f1738e62bae73ccbd184ea3e33d5a936de1b23e24c_8020'

        self.analysis_plugin.process_object(test_fw)
        result = test_fw.processed_analysis[self.analysis_plugin.NAME]
        assert 'files' in result
        assert len(result['files']) == 3
        assert result['files'][test_file_uid]['executable'] is True

    def test_process_object__error(self):
        test_fw = self._set_up_fw_for_process_object(path=os.path.join(TEST_DATA_DIR, 'usr'))

        self.analysis_plugin.process_object(test_fw)
        result = test_fw.processed_analysis[self.analysis_plugin.NAME]

        assert 'files' in result
        assert any(result['files'][uid]['executable'] for uid in result['files']) is False
        assert all(
            result['files'][uid]['results']['mips'][option]['stderr'] == '/lib/ld.so.1: No such file or directory'
            for uid in result['files']
            for option in result['files'][uid]['results']['mips'] if '--help' in option
        )

    @pytest.mark.usefixtures('execute_shell_timeout')
    def test_process_object__timeout(self):
        self.analysis_plugin._docker_is_running = lambda: True
        test_fw = self._set_up_fw_for_process_object()

        self.analysis_plugin.process_object(test_fw)
        result = test_fw.processed_analysis[self.analysis_plugin.NAME]

        assert 'files' in result
        assert any(result['files'][uid]['executable'] for uid in result['files']) is False

    def test_process_object__no_files(self):
        test_fw = create_test_firmware()
        test_fw.files_included = []

        self.analysis_plugin.process_object(test_fw)
        assert self.analysis_plugin.NAME in test_fw.processed_analysis
        assert test_fw.processed_analysis[self.analysis_plugin.NAME] == {'summary': []}

    def test_process_object__included_binary(self):
        test_fw = create_test_firmware()
        test_fw.processed_analysis['file_type']['mime'] = self.analysis_plugin.FILE_TYPES[0]

        self.analysis_plugin.process_object(test_fw)
        assert self.analysis_plugin.NAME in test_fw.processed_analysis
        assert 'parent_flag' in test_fw.processed_analysis[self.analysis_plugin.NAME]
        assert test_fw.processed_analysis[self.analysis_plugin.NAME]['parent_flag'] is True

    @pytest.mark.usefixtures('execute_shell_fails')
    def test_process_object__docker_not_running(self):
        test_fw = create_test_firmware()
        test_fw.files_included = ['foo', 'bar']
        self.analysis_plugin.process_object(test_fw)
        assert self.analysis_plugin.NAME not in test_fw.processed_analysis

    def test_docker_is_running(self):
        assert qemu_exec.docker_is_running() is True, 'Docker is not running'

    @pytest.mark.usefixtures('execute_shell_fails')
    def test_docker_is_running__not_running(self):
        assert qemu_exec.docker_is_running() is False

    def _set_up_fw_for_process_object(self, path=TEST_DATA_DIR):
        test_fw = create_test_firmware()
        test_fw.files_included = ['foo', 'bar']
        self.analysis_plugin.unpacker.set_tmp_dir(MockTmpDir(path))
        return test_fw

    def test_valid_execution_in_results(self):
        def _get_results(return_code: str, stdout: str, stderr: str):
            return {'arch': {'option': {'return_code': return_code, 'stdout': stdout, 'stderr': stderr}}}

        assert self.analysis_plugin._valid_execution_in_results(_get_results(return_code='0', stdout='', stderr='')) is False
        assert self.analysis_plugin._valid_execution_in_results(_get_results(return_code='1', stdout='', stderr='')) is False
        assert self.analysis_plugin._valid_execution_in_results(_get_results(return_code='0', stdout='something', stderr='')) is True
        assert self.analysis_plugin._valid_execution_in_results(_get_results(return_code='1', stdout='something', stderr='')) is True
        assert self.analysis_plugin._valid_execution_in_results(_get_results(return_code='0', stdout='something', stderr='error')) is True
        assert self.analysis_plugin._valid_execution_in_results(_get_results(return_code='1', stdout='something', stderr='error')) is False

    def test_parse_docker_output_options__valid(self):
        docker_output = '§#§option§#§--help§#§\n' \
                        '§#§stdout§#§standard out§#§\n' \
                        '§#§stderr§#§error§#§\n' \
                        '§#§return_code§#§123§#§'

        result = qemu_exec.parse_docker_output_options(docker_output)
        assert '--help' in result
        assert result == {'--help': {'stdout': 'standard out', 'return_code': '123', 'stderr': 'error'}}

    def test_parse_docker_output_options__multiple_options(self):
        result = qemu_exec.parse_docker_output_options(self.docker_test_output)
        assert len(result) == 2
        assert all(option in result for option in [qemu_exec.EMPTY, '--version'])

    def test_parse_docker_output_options__invalid(self):
        result = qemu_exec.parse_docker_output_options('')
        assert result == {}

    def test_parse_docker_output_strace__valid(self):
        result = qemu_exec.parse_docker_output_strace(self.docker_test_output)
        assert 'strace' in result
        result['strace'] = decompress(result['strace']).decode()
        assert result == {'strace': '38 uname(0x7ffffb38) = 0\n38 brk(NULL) = 0x004a2000\n38 brk(0x004a2cc8) = 0x004a2cc8'}

    def test_parse_docker_output_strace__invalid(self):
        result = qemu_exec.parse_docker_output_strace('')
        assert result == {}

    def test_parse_docker_output__valid(self):
        result = qemu_exec.parse_docker_output(self.docker_test_output)
        assert len(result) == 3
        assert all(k in result for k in [qemu_exec.EMPTY, '--version', 'strace'])

    def test_parse_docker_output__invalid(self):
        result = qemu_exec.parse_docker_output('')
        assert result == {}

    def test_contains_docker_error(self):
        assert qemu_exec.contains_docker_error('§#§stderr§#§Unknown syscall 4001 qemu: Unsupported syscall: 4001§#§\n') is True
        assert qemu_exec.contains_docker_error('') is False
        assert qemu_exec.contains_docker_error(self.docker_test_output) is False

    def test_process_qemu_job(self):
        tmp = qemu_exec.test_qemu_executability
        qemu_exec.test_qemu_executability = lambda file_path, arch_suffix, root_path: {'--option': {'stdout': 'test', 'stderr': '', 'return_code': '0'}}

        results = {}
        qemu_exec.process_qemu_job('test_path', 'test_arch', 'test_root', results, 'test_uid')
        assert results == {'test_uid': {'path': 'test_path', 'results': {'test_arch': {'--option': {'stdout': 'test', 'stderr': '', 'return_code': '0'}}}}}

        qemu_exec.process_qemu_job('test_path', 'test_arch_2', 'test_root', results, 'test_uid')
        assert results == {'test_uid': {'path': 'test_path', 'results': {
            'test_arch': {'--option': {'stderr': '', 'return_code': '0', 'stdout': 'test'}},
            'test_arch_2': {'--option': {'stderr': '', 'return_code': '0', 'stdout': 'test'}}
        }}}

        qemu_exec.test_qemu_executability = tmp

    def test_get_summary(self):
        analysis_result = {}
        result = self.analysis_plugin._get_summary(analysis_result)
        assert result == []

        analysis_result.update({'foo': {'executable': False}})
        result = self.analysis_plugin._get_summary(analysis_result)
        assert result == []

        analysis_result.update({'bar': {'executable': True}})
        result = self.analysis_plugin._get_summary(analysis_result)
        assert result == ['executable']

    def test_merge_similar_entries(self):
        test_dict = {
            'option_1': {'a': 'x', 'b': 'x', 'c': 'x'},
            'option_2': {'a': 'x', 'b': 'x', 'c': 'x'},
            'option_3': {'a': 'x', 'b': 'x'},
            'option_4': {'a': 'y', 'b': 'y', 'c': 'y'},
            'option_5': {'a': 'x', 'b': 'x', 'c': 'x'},
        }
        qemu_exec.merge_similar_entries(test_dict)
        assert len(test_dict) == 3
        assert any(all(option in k for option in ['option_1', 'option_2', 'option_5']) for k in test_dict)


class TestQemuExecUnpacker(TestCase):

    def setUp(self):
        self.name_prefix = 'FACT_plugin_qemu'
        self.config = get_config_for_testing()
        self.unpacker = qemu_exec.Unpacker(config=self.config)
        qemu_exec.BinaryServiceDbInterface = MockBinaryService

    def test_unpack_fo(self):
        test_fw = create_test_firmware()
        tmp_dir = self.unpacker.unpack_fo(test_fw)

        try:
            assert self.name_prefix in tmp_dir.name
            content = os.listdir(tmp_dir.name)
            assert content != []
            assert 'get_files_test' in content
        finally:
            tmp_dir.cleanup()

    def test_unpack_fo__no_file_path(self):
        test_fw = create_test_firmware()
        test_fw.file_path = None

        tmp_dir = self.unpacker.unpack_fo(test_fw)

        try:
            assert self.name_prefix in tmp_dir.name
            content = os.listdir(tmp_dir.name)
            assert content != []
            assert 'get_files_test' in content
        finally:
            tmp_dir.cleanup()

    def test_unpack_fo__path_not_found(self):
        test_fw = create_test_firmware()
        test_fw.file_path = 'foo/bar'
        tmp_dir = self.unpacker.unpack_fo(test_fw)

        assert tmp_dir is None
        with suppress(AttributeError):
            tmp_dir.cleanup()

    def test_unpack_fo__binary_not_found(self):
        test_fw = create_test_firmware()
        test_fw.uid = 'foo'
        test_fw.file_path = None
        tmp_dir = self.unpacker.unpack_fo(test_fw)

        assert tmp_dir is None
        with suppress(AttributeError):
            tmp_dir.cleanup()


class MockBinaryService:
    def __init__(self, config=None):
        self.config = config

    def get_file_name_and_path(self, uid):
        if uid != 'foo':
            return {'file_path': os.path.join(get_test_data_dir(), 'container/test.zip')}
        return None

    def shutdown(self):
        pass
