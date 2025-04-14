from __future__ import annotations

from base64 import b64decode, b64encode
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory

import pytest
from common_helper_files import get_dir_of_file
from requests.exceptions import ConnectionError as RequestConnectionError
from requests.exceptions import ReadTimeout

from test.common_helper import get_test_data_dir
from test.mock import mock_patch

from ..code import qemu_exec
from ..code.qemu_exec import EXECUTABLE, AnalysisPlugin

TEST_DATA_DIR = Path(get_dir_of_file(__file__)) / 'data/test_tmp_dir'
TEST_DATA_DIR_2 = Path(get_dir_of_file(__file__)) / 'data/test_tmp_dir_2'
TEST_DATA_DIR_3 = Path(get_dir_of_file(__file__)) / 'data/other_architectures'
CLI_PARAMETERS = ['-h', '--help', '-help', '--version', ' ']


class MockTmpDir:
    def __init__(self, name: Path | str):
        self.name = str(name)

    def cleanup(self):
        pass


class MockUnpacker:
    tmp_dir = None

    @contextmanager
    def unpack_file(self, _):
        yield self.tmp_dir.name

    def set_tmp_dir(self, tmp_dir):
        self.tmp_dir = tmp_dir

    @staticmethod
    def get_extracted_files_dir(base_dir):
        return Path(base_dir)


@pytest.fixture
def execute_shell_fails(monkeypatch):  # noqa: PT004
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
    class containers:  # noqa: N801
        @staticmethod
        def run(_, command, **___):
            if 'file-with-error' in command:
                raise RequestConnectionError()
            if 'json-error' in command:
                return ContainerMock()
            raise ReadTimeout()


@pytest.fixture
def execute_docker_error(monkeypatch):  # noqa: PT004
    monkeypatch.setattr('docker.client.from_env', DockerClientMock)


@pytest.fixture
def _mock_unpacker(monkeypatch):
    monkeypatch.setattr('plugins.analysis.qemu_exec.code.qemu_exec.Unpacker', MockUnpacker)


def test_find_relevant_files():
    tmp_dir = MockTmpDir(str(TEST_DATA_DIR))
    result = sorted(qemu_exec._find_relevant_files(Path(tmp_dir.name), root_path=Path(tmp_dir.name)))
    assert len(result) == 4

    path_list, mime_types = list(zip(*result))
    for path in ['/lib/ld.so.1', '/lib/libc.so.6', '/test_mips_static', '/usr/bin/test_mips']:
        assert path in path_list
    assert all('MIPS' in mime for mime in mime_types)


def test_check_qemu_executability():
    result = qemu_exec.check_qemu_executability('/test_mips_static', 'mips', TEST_DATA_DIR)
    assert any('--help' in option for option in result)
    option = [option for option in result if '--help' in option][0]
    assert result[option]['stdout'] == 'Hello World\n'
    assert result[option]['stderr'] == ''
    assert result[option]['return_code'] == '0'

    result = qemu_exec.check_qemu_executability('/test_mips_static', 'i386', TEST_DATA_DIR)
    assert result == {}


def test_find_arch_suffixes():
    mime_str = 'ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked'
    result = qemu_exec._find_arch_suffixes(mime_str)
    assert result != []
    # the more specific architecture variants should be checked first
    assert result == qemu_exec.ARCH_TO_BIN_DICT['MIPS32']
    assert result != qemu_exec.ARCH_TO_BIN_DICT['MIPS']


def test_find_arch_suffixes__unknown_arch():
    mime_str = 'foo'
    result = qemu_exec._find_arch_suffixes(mime_str)
    assert result == []


@pytest.mark.timeout(10)
def test_process_included_files():
    test_uid = '6b4142fa7e0a35ff6d10e18654be8ac5b778c3b5e2d3d345d1a01c2bcbd51d33_676340'
    file_list = [('/test_mips_static', '-MIPS32-')]

    result = qemu_exec._process_included_files(file_list, root_path=Path(TEST_DATA_DIR))
    assert test_uid in result
    assert result[test_uid]['executable'] is True


@dataclass
class MockFileTypeResult:
    mime: str
    full: str


@dataclass
class MockFile:
    name: str


MOCK_ANALYSES = {'file_type': MockFileTypeResult(mime='test_type', full='Not a PE file')}
MOCK_ANALYSES_EXECUTABLE = {
    'file_type': MockFileTypeResult(mime='application/x-executable', full='ELF 64-bit executable')
}


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestPluginQemuExec:
    @pytest.mark.usefixtures('_mock_unpacker')
    @pytest.mark.timeout(15)
    def test_process_object(self, analysis_plugin: AnalysisPlugin):
        analysis_plugin.OPTIONS = ['-h']
        analysis_plugin.unpacker.set_tmp_dir(MockTmpDir(TEST_DATA_DIR))

        result = analysis_plugin.analyze(MockFile(name=''), {}, MOCK_ANALYSES)
        assert len(result.included_file_results) == 4
        assert any(file.is_executable for file in result.included_file_results)
        paths = sorted(file.path for file in result.included_file_results)
        assert paths == ['/lib/ld.so.1', '/lib/libc.so.6', '/test_mips_static', '/usr/bin/test_mips']

        summary = analysis_plugin.summarize(result)
        assert summary == [EXECUTABLE]

    @pytest.mark.usefixtures('_mock_unpacker')
    @pytest.mark.timeout(15)
    def test_process_object__with_extracted_folder(self, analysis_plugin: AnalysisPlugin):
        analysis_plugin.OPTIONS = ['-h']
        analysis_plugin.unpacker.set_tmp_dir(MockTmpDir(TEST_DATA_DIR_2))
        test_file_uid = '68bbef24a7083ca2f5dc93f1738e62bae73ccbd184ea3e33d5a936de1b23e24c_8020'

        result = analysis_plugin.analyze(MockFile(name=''), {}, MOCK_ANALYSES)
        assert len(result.included_file_results) == 3
        file_result_by_uid = {file.uid: file for file in result.included_file_results}
        assert file_result_by_uid[test_file_uid].is_executable is True

    @pytest.mark.usefixtures('_mock_unpacker')
    @pytest.mark.timeout(10)
    def test_process_object__error(self, analysis_plugin):
        analysis_plugin.unpacker.set_tmp_dir(MockTmpDir(TEST_DATA_DIR / 'usr'))
        result = analysis_plugin.analyze(MockFile(name=''), {}, MOCK_ANALYSES)
        summary = analysis_plugin.summarize(result)

        assert len(result.included_file_results) == 1
        file_result = result.included_file_results[0]
        assert file_result.is_executable is False
        assert len(file_result.extended_results) == 1
        arch_result = file_result.extended_results[0]
        assert arch_result.architecture == 'mips'
        assert all(
            "/lib/ld.so.1': No such file or directory" in parameter_result.stderr
            for parameter_result in arch_result.parameter_results
        )
        assert summary == []

    @pytest.mark.timeout(10)
    @pytest.mark.usefixtures('_mock_unpacker', 'execute_docker_error')
    def test_process_object__timeout(self, analysis_plugin):
        analysis_plugin.unpacker.set_tmp_dir(MockTmpDir(TEST_DATA_DIR / 'usr'))
        result = analysis_plugin.analyze(MockFile(name=''), {}, MOCK_ANALYSES)

        assert len(result.included_file_results) == 1
        file_result = result.included_file_results[0]
        assert file_result.is_executable is False
        assert all(arch_results.error == 'timeout' for arch_results in file_result.extended_results)

    @pytest.mark.usefixtures('_mock_unpacker')
    @pytest.mark.timeout(10)
    def test_process_object__no_files(self, analysis_plugin):
        with TemporaryDirectory() as tmp_dir:
            analysis_plugin.unpacker.set_tmp_dir(MockTmpDir(tmp_dir))
            result = analysis_plugin.analyze(MockFile(name=''), {}, MOCK_ANALYSES)
            summary = analysis_plugin.summarize(result)

        assert len(result.included_file_results) == 0
        assert summary == []

    @pytest.mark.usefixtures('_mock_unpacker')
    @pytest.mark.timeout(10)
    def test_process_object__included_binary(self, analysis_plugin):
        analysis_plugin.unpacker.set_tmp_dir(MockTmpDir(TEST_DATA_DIR))
        result = analysis_plugin.analyze(MockFile(name=''), {}, MOCK_ANALYSES_EXECUTABLE)
        assert result.parent_flag is True
        assert len(result.included_file_results) == 0


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


def test_get_docker_output__timeout(execute_docker_error):  # noqa: ARG001
    result = qemu_exec.get_docker_output('mips', '/test_mips_static', TEST_DATA_DIR)
    assert 'error' in result
    assert result['error'] == 'timeout'


def test_get_docker_output__error(execute_docker_error):  # noqa: ARG001
    result = qemu_exec.get_docker_output('mips', '/file-with-error', TEST_DATA_DIR)
    assert 'error' in result
    assert result['error'] == 'process error'


def test_get_docker_output__json_error(execute_docker_error):  # noqa: ARG001
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
    ('input_data', 'expected_output'),
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
    ('input_data', 'expected_output'),
    [
        ({}, False),
        ({'return_code': '0', 'stdout': '', 'stderr': ''}, False),
        ({'return_code': '1', 'stdout': '', 'stderr': ''}, False),
        ({'return_code': '0', 'stdout': 'something', 'stderr': ''}, True),
        ({'return_code': '1', 'stdout': 'something', 'stderr': ''}, True),
        ({'return_code': '0', 'stdout': 'something', 'stderr': 'error'}, True),
        ({'return_code': '1', 'stdout': 'something', 'stderr': 'error'}, False),
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
    ('input_data', 'expected_output'),
    [
        ({'parameter': {'std_out': 'foo Invalid ELF bar'}}, True),
        ({'parameter': {'std_out': 'no errors'}}, False),
    ],
)
def test_result_contains_qemu_errors(input_data, expected_output):
    assert qemu_exec.result_contains_qemu_errors(input_data) == expected_output


@pytest.mark.parametrize(
    ('input_data', 'expected_output'),
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
    ('input_data', 'expected_output'),
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
    assert input_data['strace'] is None


def test_process_strace_output():
    input_data = {'strace': {'stdout': 'foobar'}}
    qemu_exec.process_strace_output(input_data)
    result = input_data['strace']
    assert isinstance(result, str)
    assert b64decode(result)[:2].hex() == '789c'  # magic string for zlib compressed data


class TestQemuExecUnpacker:
    def setup_method(self):
        self.name_prefix = 'FACT_plugin_qemu'
        self.unpacker = qemu_exec.Unpacker()

    def test_unpack_fo(self):
        with self.unpacker.unpack_file(get_test_data_dir() / 'container/test.zip') as tmp_dir:
            assert self.name_prefix in tmp_dir
            content = [p.name for p in Path(tmp_dir, 'files').iterdir()]
            assert content != []
            assert 'get_files_test' in content

    def test_unpack_fo__path_not_found(self):
        with self.unpacker.unpack_file('foo/bar') as tmp_dir:
            assert tmp_dir is None
