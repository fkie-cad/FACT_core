import pytest

from helperFunctions.install import apt_install_packages, apt_remove_packages, pip_install_packages, \
    pip_remove_packages, apt_update_sources, apt_upgrade_system, check_if_command_in_path, \
    check_if_executable_in_bin_folder, InstallationError


def _patch_shell_command(patch, mock_output: str, mock_return_code: int):
    patch.setattr('helperFunctions.install.execute_shell_command_get_return_code', lambda shell_command, timeout=None: (mock_output, mock_return_code))


def test_apt_update_system(monkeypatch):
    _patch_shell_command(monkeypatch, 'update successful\n', 0)
    assert 'update success' in apt_update_sources()


def test_apt_update_system_fails(monkeypatch):
    _patch_shell_command(monkeypatch, 'update failed\n', 255)
    with pytest.raises(InstallationError):
        apt_update_sources()


def test_apt_upgrade_system(monkeypatch):
    _patch_shell_command(monkeypatch, 'upgrade successful\n', 0)
    assert 'upgrade success' in apt_upgrade_system()


def test_apt_upgrade_system_fails(monkeypatch):
    _patch_shell_command(monkeypatch, 'upgrade failed\n', 255)
    with pytest.raises(InstallationError):
        apt_upgrade_system()
