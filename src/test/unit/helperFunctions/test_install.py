import pytest

from helperFunctions.install import apt_autoremove_packages, apt_clean_system, apt_install_packages, apt_remove_packages, pip_install_packages, pip_remove_packages, apt_update_sources, apt_upgrade_system, check_if_command_in_path, check_if_executable_in_bin_folder, InstallationError


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


def test_apt_autoremove_packages(monkeypatch):
    _patch_shell_command(monkeypatch, 'removal succeeded\n', 0)
    assert 'succeeded' in apt_autoremove_packages()


def test_apt_autoremove_packages_fails(monkeypatch):
    _patch_shell_command(monkeypatch, 'removal failed\n', 255)
    with pytest.raises(InstallationError):
        apt_autoremove_packages()


def test_apt_clean_system(monkeypatch):
    _patch_shell_command(monkeypatch, 'clean successful\n', 0)
    assert 'clean success' in apt_clean_system()


def test_apt_clean_system_fails(monkeypatch):
    _patch_shell_command(monkeypatch, 'clean failed\n', 255)
    with pytest.raises(InstallationError):
        apt_clean_system()


def test_apt_install_packages(monkeypatch):
    _patch_shell_command(monkeypatch, 'mockpackage successfully installed\n', 0)
    assert 'mockpackage success' in apt_install_packages('mockpackage')

    assert 'mockpackage success' in apt_install_packages('mockpackage', 'another_package')


def test_apt_install_package_fails(monkeypatch):
    _patch_shell_command(monkeypatch, 'something went wrong\n', 255)
    with pytest.raises(InstallationError):
        apt_install_packages('mockpackage')


def test_apt_remove_packages(monkeypatch):
    _patch_shell_command(monkeypatch, 'mockpackage successfully removed\n', 0)
    assert 'mockpackage success' in apt_remove_packages('mockpackage')

    assert 'mockpackage success' in apt_remove_packages('mockpackage', 'another_package')


def test_apt_remove_package_fails(monkeypatch):
    _patch_shell_command(monkeypatch, 'something went wrong\n', 255)
    with pytest.raises(InstallationError):
        apt_remove_packages('mockpackage')
