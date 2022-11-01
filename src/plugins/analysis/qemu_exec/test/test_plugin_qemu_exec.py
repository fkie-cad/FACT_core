# pylint: disable=protected-access, no-self-use,wrong-import-order,invalid-name,unused-argument,redefined-outer-name
import os
from base64 import b64decode, b64encode
from pathlib import Path
from subprocess import CompletedProcess
from unittest import TestCase

import pytest
from common_helper_files import get_dir_of_file
from requests.exceptions import ConnectionError as RequestConnectionError
from requests.exceptions import ReadTimeout

from test.common_helper import TEST_FW, CommonDatabaseMock, create_test_firmware, get_test_data_dir
from test.mock import mock_patch
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code import qemu_exec
from ..code.qemu_exec import EXECUTABLE, AnalysisPlugin

TEST_DATA_DIR = Path(get_dir_of_file(__file__)) / 'data/test_tmp_dir'
TEST_DATA_DIR_2 = Path(get_dir_of_file(__file__)) / 'data/test_tmp_dir_2'
TEST_DATA_DIR_3 = Path(get_dir_of_file(__file__)) / 'data/other_architectures'
CLI_PARAMETERS = ['-h', '--help', '-help', '--version', ' ']


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

    @staticmethod
    def get_extracted_files_dir(base_dir):
        return Path(base_dir)


@pytest.fixture
def execute_shell_fails(monkeypatch):
    monkeypatch.setattr(qemu_exec, 'subprocess.run', CompletedProcess('DONT_CARE', 1))


class ContainerMock:
    @staticmethod
    def wait(**_):
        return {'StatusCode': 0}

    @staticmethod
    def stop():
        pass

    @staticmethod
    def remove():
        pass

    @staticmethod
    def logs(**_):
        return b'not json decodable'


class DockerClientMock:
    class containers:
        @staticmethod
        def run(_, command, **___):
            if 'file-with-error' in command:
                raise RequestConnectionError()
            if 'json-error' in command:
                return ContainerMock()
            raise ReadTimeout()


@pytest.fixture
def execute_docker_error(monkeypatch):
    monkeypatch.setattr('docker.client.from_env', DockerClientMock)


class TestPluginQemuExec(AnalysisPluginTest):

    PLUGIN_NAME = 'qemu_exec'
    PLUGIN_CLASS = AnalysisPlugin

    def setup_plugin(self):
        return AnalysisPlugin(unpacker=MockUnpacker(), view_updater=CommonDatabaseMock())

    def test_has_relevant_type(self):
        assert self.analysis_plugin._has_relevant_type(None) is False
        assert self.analysis_plugin._has_relevant_type({'mime': 'foo'}) is False
        assert self.analysis_plugin._has_relevant_type({'mime': 'application/x-executable'}) is True

    def test_find_relevant_files(self):
        tmp_dir = MockTmpDir(str(TEST_DATA_DIR))

        self.analysis_plugin.root_path = tmp_dir.name
        self.analysis_plugin.unpacker.set_tmp_dir(tmp_dir)
        result = sorted(self.analysis_plugin._find_relevant_files(Path(tmp_dir.name)))
        assert len(result) == 4

        path_list, mime_types = list(zip(*result))
        for path in ['/lib/ld.so.1', '/lib/libc.so.6', '/test_mips_static', '/usr/bin/test_mips']:
            assert path in path_list
        assert all('MIPS' in mime for mime in mime_types)

    def test_check_qemu_executability(self):
        self.analysis_plugin.OPTIONS = ['-h']

        result = qemu_exec.check_qemu_executability('/test_mips_static', 'mips', TEST_DATA_DIR)
        assert any('--help' in option for option in result)
        option = [option for option in result if '--help' in option][0]
        assert result[option]['stdout'] == 'Hello World\n'
        assert result[option]['stderr'] == ''
        assert result[option]['return_code'] == '0'

        result = qemu_exec.check_qemu_executability('/test_mips_static', 'i386', TEST_DATA_DIR)
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

    @pytest.mark.timeout(10)
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

    @pytest.mark.timeout(15)
    def test_process_object(self):
        self.analysis_plugin.OPTIONS = ['-h']
        test_fw = self._set_up_fw_for_process_object()

        self.analysis_plugin.process_object(test_fw)
        result = test_fw.processed_analysis[self.analysis_plugin.NAME]
        assert 'files' in result
        assert len(result['files']) == 4
        assert any(result['files'][uid]['executable'] for uid in result['files'])

    @pytest.mark.timeout(15)
    def test_process_object__with_extracted_folder(self):
        self.analysis_plugin.OPTIONS = ['-h']
        test_fw = self._set_up_fw_for_process_object(path=TEST_DATA_DIR_2)
        test_file_uid = '68bbef24a7083ca2f5dc93f1738e62bae73ccbd184ea3e33d5a936de1b23e24c_8020'

        self.analysis_plugin.process_object(test_fw)
        result = test_fw.processed_analysis[self.analysis_plugin.NAME]
        assert 'files' in result
        assert len(result['files']) == 3
        assert result['files'][test_file_uid]['executable'] is True

    @pytest.mark.timeout(10)
    def test_process_object__error(self):
        test_fw = self._set_up_fw_for_process_object(path=TEST_DATA_DIR / 'usr')

        self.analysis_plugin.process_object(test_fw)
        result = test_fw.processed_analysis[self.analysis_plugin.NAME]

        assert 'files' in result
        assert any(result['files'][uid]['executable'] for uid in result['files']) is False
        assert all(
            '/lib/ld.so.1\': No such file or directory' in result['files'][uid]['results']['mips'][option]['stderr']
            for uid in result['files']
            for option in result['files'][uid]['results']['mips']
            if option != 'strace'
        )

    @pytest.mark.timeout(10)
    @pytest.mark.usefixtures('execute_docker_error')
    def test_process_object__timeout(self):
        test_fw = self._set_up_fw_for_process_object()

        self.analysis_plugin.process_object(test_fw)
        result = test_fw.processed_analysis[self.analysis_plugin.NAME]

        assert 'files' in result
        assert all(
            arch_results['error'] == 'timeout'
            for uid in result['files']
            for arch_results in result['files'][uid]['results'].values()
        )
        assert all(result['files'][uid]['executable'] is False for uid in result['files'])

    @pytest.mark.timeout(10)
    def test_process_object__no_files(self):
        test_fw = create_test_firmware()
        test_fw.files_included = []

        self.analysis_plugin.process_object(test_fw)
        assert self.analysis_plugin.NAME in test_fw.processed_analysis
        assert test_fw.processed_analysis[self.analysis_plugin.NAME] == {'summary': []}

    @pytest.mark.timeout(10)
    def test_process_object__included_binary(self):
        test_fw = create_test_firmware()
        test_fw.processed_analysis['file_type']['mime'] = self.analysis_plugin.FILE_TYPES[0]

        self.analysis_plugin.process_object(test_fw)
        assert self.analysis_plugin.NAME in test_fw.processed_analysis
        assert 'parent_flag' in test_fw.processed_analysis[self.analysis_plugin.NAME]
        assert test_fw.processed_analysis[self.analysis_plugin.NAME]['parent_flag'] is True

    def _set_up_fw_for_process_object(self, path: Path = TEST_DATA_DIR):
        test_fw = create_test_firmware()
        test_fw.files_included = ['foo', 'bar']
        self.analysis_plugin.unpacker.set_tmp_dir(MockTmpDir(str(path)))
        return test_fw


def test_get_docker_output__static():
    result = qemu_exec.get_docker_output('mips', '/test_mips_static', TEST_DATA_DIR)
    _check_result(result)


def test_get_docker_output__dynamic():
    result = qemu_exec.get_docker_output('mips', '/usr/bin/test_mips', TEST_DATA_DIR)
    _check_result(result)


def test_get_docker_output__arm():
    result = qemu_exec.get_docker_output('arm', '/test_arm_static', TEST_DATA_DIR_3)
    _check_result(result)


def test_get_docker_output__ppc():
    result = qemu_exec.get_docker_output('ppc', '/test_ppc_static', TEST_DATA_DIR_3)
    _check_result(result)


def _check_result(result):
    for parameter in CLI_PARAMETERS:
        assert parameter in result
        assert 'error' not in result[parameter]
        assert b'Hello World' in b64decode(result[parameter]['stdout'])
    assert 'strace' in result


def test_get_docker_output__wrong_arch():
    result = qemu_exec.get_docker_output('i386', '/test_mips_static', TEST_DATA_DIR)
    assert all(b'Invalid ELF image' in b64decode(result_dict['stderr']) for result_dict in result.values())


def test_get_docker_output__timeout(execute_docker_error):
    result = qemu_exec.get_docker_output('mips', '/test_mips_static', TEST_DATA_DIR)
    assert 'error' in result
    assert result['error'] == 'timeout'


def test_get_docker_output__error(execute_docker_error):
    result = qemu_exec.get_docker_output('mips', '/file-with-error', TEST_DATA_DIR)
    assert 'error' in result
    assert result['error'] == 'process error'


def test_get_docker_output__json_error(execute_docker_error):
    result = qemu_exec.get_docker_output('mips', '/json-error', TEST_DATA_DIR)
    assert 'error' in result
    assert result['error'] == 'could not decode result'


def test_process_qemu_job():
    test_results = {'--option': {'stdout': 'test', 'stderr': '', 'return_code': '0'}}
    uid = 'test_uid'
    results = {}

    with mock_patch(qemu_exec, 'check_qemu_executability', lambda *_: test_results):
        qemu_exec.process_qemu_job('test_path', 'test_arch', Path('test_root'), results, uid)
        assert results == {uid: {'path': 'test_path', 'results': {'test_arch': test_results}}}

        qemu_exec.process_qemu_job('test_path', 'test_arch_2', Path('test_root'), results, uid)
        assert results == {
            uid: {'path': 'test_path', 'results': {'test_arch': test_results, 'test_arch_2': test_results}}
        }


@pytest.mark.parametrize(
    'input_data, expected_output',
    [
        ({}, []),
        ({'foo': {EXECUTABLE: False}}, []),
        ({'foo': {EXECUTABLE: False}, 'bar': {EXECUTABLE: True}}, [EXECUTABLE]),
    ],
)
def test_get_summary(input_data, expected_output):
    result = qemu_exec.AnalysisPlugin._get_summary(input_data)
    assert result == expected_output


@pytest.mark.parametrize(
    'input_data, expected_output',
    [
        ({}, False),
        ({'arch': {}}, False),
        ({'arch': {'option': {}}}, False),
        ({'arch': {'error': 'foo'}}, False),
        ({'arch': {'option': {'error': 'foo'}}}, False),
        ({'arch': {'option': {'stdout': 'foo', 'stderr': '', 'return_code': '0'}}}, True),
    ],
)
def test_valid_execution_in_results(input_data, expected_output):
    assert qemu_exec._valid_execution_in_results(input_data) == expected_output


@pytest.mark.parametrize(
    'input_data, expected_output',
    [
        ({}, False),
        (dict(return_code='0', stdout='', stderr=''), False),
        (dict(return_code='1', stdout='', stderr=''), False),
        (dict(return_code='0', stdout='something', stderr=''), True),
        (dict(return_code='1', stdout='something', stderr=''), True),
        (dict(return_code='0', stdout='something', stderr='error'), True),
        (dict(return_code='1', stdout='something', stderr='error'), False),
    ],
)
def test_output_without_error_exists(input_data, expected_output):
    assert qemu_exec._output_without_error_exists(input_data) == expected_output


def test_merge_similar_entries():
    test_dict = {
        'option_1': {'a': 'x', 'b': 'x', 'c': 'x'},
        'option_2': {'a': 'x', 'b': 'x', 'c': 'x'},
        'option_3': {'a': 'x', 'b': 'x'},
        'option_4': {'a': 'y', 'b': 'y', 'c': 'y'},
        'option_5': {'a': 'x', 'b': 'x', 'c': 'x'},
    }
    qemu_exec.merge_identical_results(test_dict)
    assert len(test_dict) == 3
    assert any(all(option in k for option in ['option_1', 'option_2', 'option_5']) for k in test_dict)


@pytest.mark.parametrize(
    'input_data, expected_output',
    [
        ({'parameter': {'std_out': 'foo Invalid ELF bar'}}, True),
        ({'parameter': {'std_out': 'no errors'}}, False),
    ],
)
def test_result_contains_qemu_errors(input_data, expected_output):
    assert qemu_exec.result_contains_qemu_errors(input_data) == expected_output


@pytest.mark.parametrize(
    'input_data, expected_output',
    [
        ('Unknown syscall 4001 qemu: Unsupported syscall: 4001\n', True),
        ('foobar', False),
        ('', False),
    ],
)
def test_contains_docker_error(input_data, expected_output):
    assert qemu_exec.contains_docker_error(input_data) == expected_output


def test_replace_empty_strings():
    test_input = {
        '-h': {'std_out': '', 'std_err': '', 'return_code': '0'},
        ' ': {'std_out': '', 'std_err': '', 'return_code': '0'},
    }
    qemu_exec.replace_empty_strings(test_input)
    assert ' ' not in test_input
    assert qemu_exec.EMPTY in test_input
    assert '-h' in test_input


@pytest.mark.parametrize(
    'input_data, expected_output',
    [
        ({'parameter': {'output': 0}}, '0'),
        ({'parameter': {'output': b64encode(b'').decode()}}, ''),
        ({'parameter': {'output': b64encode(b'foobar').decode()}}, 'foobar'),
        ({'parameter': {'output': 'no_b64'}}, 'decoding error: no_b64'),
    ],
)
def test_decode_output_values(input_data, expected_output):
    results = qemu_exec.decode_output_values(input_data)
    assert all(isinstance(value, str) for parameter_result in results.values() for value in parameter_result.values())
    assert results['parameter']['output'] == expected_output


@pytest.mark.parametrize(
    'input_data',
    [
        {},
        {'strace': {}},
        {'strace': {'error': 'foo'}},
        {'strace': {'stdout': ''}},
    ],
)
def test_process_strace_output__no_strace(input_data):
    qemu_exec.process_strace_output(input_data)
    assert input_data['strace'] == {}


def test_process_strace_output():
    input_data = {'strace': {'stdout': 'foobar'}}
    qemu_exec.process_strace_output(input_data)
    result = input_data['strace']
    assert isinstance(result, str)
    assert b64decode(result)[:2].hex() == '789c'  # magic string for zlib compressed data


class TestQemuExecUnpacker(TestCase):
    def setUp(self):
        self.name_prefix = 'FACT_plugin_qemu'
        self.unpacker = qemu_exec.Unpacker()
        qemu_exec.FSOrganizer = MockFSOrganizer

    def test_unpack_fo(self):
        test_fw = create_test_firmware()
        tmp_dir = self.unpacker.unpack_fo(test_fw)

        try:
            assert self.name_prefix in tmp_dir.name
            content = os.listdir(str(Path(tmp_dir.name, 'files')))
            assert content != []
            assert 'get_files_test' in content
        finally:
            tmp_dir.cleanup()

    def test_unpack_fo__no_file_path(self):
        test_fw = create_test_firmware()
        test_fw.file_path = None

        with mock_patch(self.unpacker.fs_organizer, 'generate_path', lambda _: TEST_FW.file_path):
            tmp_dir = self.unpacker.unpack_fo(test_fw)

        try:
            assert self.name_prefix in tmp_dir.name
            content = os.listdir(str(Path(tmp_dir.name, 'files')))
            assert content != []
            assert 'get_files_test' in content
        finally:
            tmp_dir.cleanup()

    def test_unpack_fo__path_not_found(self):
        test_fw = create_test_firmware()
        test_fw.file_path = 'foo/bar'
        tmp_dir = self.unpacker.unpack_fo(test_fw)

        assert tmp_dir is None

    def test_unpack_fo__binary_not_found(self):
        test_fw = create_test_firmware()
        test_fw.uid = 'foo'
        test_fw.file_path = None
        tmp_dir = self.unpacker.unpack_fo(test_fw)

        assert tmp_dir is None


class MockFSOrganizer:
    @staticmethod
    def generate_path(fo):
        if fo.uid != 'foo':
            return os.path.join(get_test_data_dir(), 'container/test.zip')
        return None
