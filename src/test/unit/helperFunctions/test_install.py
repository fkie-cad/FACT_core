import pytest

from helperFunctions.install import InstallationError, run_shell_command_raise_on_return_code


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
