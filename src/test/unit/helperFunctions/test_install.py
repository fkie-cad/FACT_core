import os
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from helperFunctions.install import (
    InstallationError, OperateInDirectory, check_string_in_command, run_shell_command_raise_on_return_code
)


def _patch_shell_command(patch, mock_output: str, mock_return_code: int):
    patch.setattr('helperFunctions.install.execute_shell_command_get_return_code', lambda shell_command, timeout=None: (mock_output, mock_return_code))


def test_run_command_succeeds():
    output = run_shell_command_raise_on_return_code('true', 'anything')
    assert not output


def test_run_command_fails():
    with pytest.raises(InstallationError) as installation_error:
        run_shell_command_raise_on_return_code('false', 'anything')
    assert 'anything' in str(installation_error.value)


def test_run_command_append_output():
    with pytest.raises(InstallationError) as installation_error:
        run_shell_command_raise_on_return_code('echo "additional information" && false', 'anything', True)
    assert 'anything' in str(installation_error.value)
    assert 'additional information' in str(installation_error.value)


def test_operate_in_directory():
    '''
    TempDir structure:
      ├ file1
      └ folder
        └ file2
    '''
    with TemporaryDirectory('fact_test') as tmp_dir:
        tmp_path = Path(tmp_dir)
        folder = tmp_path / 'folder'
        folder.mkdir()
        file1 = tmp_path / 'file1'
        file1.touch()
        file2 = folder / 'file2'
        file2.touch()
        assert not (Path(file1.name).is_file() or Path(file2.name).is_file() or Path(folder.name).is_dir())

        current_dir = os.getcwd()
        with OperateInDirectory(tmp_dir):
            assert Path(file1.name).is_file()
            assert current_dir != os.getcwd()
        assert current_dir == os.getcwd()

        with OperateInDirectory(folder, remove=True):
            assert Path(file2.name).is_file()
        assert file1.is_file() and not file2.is_file() and not folder.is_dir()


@pytest.mark.parametrize('command, string, expected_output', [
    ('echo test', 'test', True),
    ('echo abcdef', 'bcde', True),
    ('echo abcdef', 'xyz', False),
    ('false', 'false', False),
])
def test_check_string_in_command(command, string, expected_output):
    assert check_string_in_command(command, string) == expected_output
