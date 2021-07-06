import configparser
import logging
import os
import shutil
from pathlib import Path
from typing import List, Tuple, Union

from common_helper_process import execute_shell_command_get_return_code


class InstallationError(Exception):
    '''
    Class representing all expected errors that happen during installation, such as timeouts on remote hosts.
    '''


class OperateInDirectory:
    '''
    Context manager allowing to execute a number of commands in a given directory. On exit, the working directory is
    changed back to its previous value.

    :param target_directory: Directory path to use as working directory.
    :param remove: Optional boolean to indicate if `target_directory` should be removed on exit.
    '''
    def __init__(self, target_directory: Union[str, Path], remove: bool = False):
        self._current_working_dir = None
        self._target_directory = str(target_directory)
        self._remove = remove

    def __enter__(self):
        self._current_working_dir = os.getcwd()
        os.chdir(self._target_directory)

    def __exit__(self, *args):
        os.chdir(self._current_working_dir)
        if self._remove:
            remove_folder(self._target_directory)


def remove_folder(folder_name: str):
    '''
    Python equivalent to `rm -rf`. Remove a directory an all included files. If administrative rights are necessary,
    this effectively falls back to `sudo rm -rf`.

    :param folder_name: Path to directory to remove.
    '''
    try:
        shutil.rmtree(folder_name)
    except PermissionError:
        logging.debug('Falling back on root permission for deleting {}'.format(folder_name))
        execute_shell_command_get_return_code('sudo rm -rf {}'.format(folder_name))
    except Exception as exception:
        raise InstallationError(exception) from None


def log_current_packages(packages: Tuple[str], install: bool = True):
    '''
    Log which packages are installed or removed.

    :param packages: List of packages that are affected.
    :param install: Identifier to distinguish installation from removal.
    '''
    action = 'Installing' if install else 'Removing'
    logging.info('{} {}'.format(action, ' '.join(packages)))


def _run_shell_command_raise_on_return_code(command: str, error: str, add_output_on_error=False) -> str:  # pylint: disable=invalid-name
    output, return_code = execute_shell_command_get_return_code(command)
    if return_code != 0:
        if add_output_on_error:
            error = '{}\n{}'.format(error, output)
        raise InstallationError(error)
    return output


def dnf_update_sources():
    '''
    Update package lists on Fedora / RedHat / Cent systems.
    '''
    return _run_shell_command_raise_on_return_code('sudo dnf update -y', 'Unable to update')


def dnf_install_packages(*packages: str):
    '''
    Install packages on Fedora / RedHat / Cent systems.

    :param packages: Iterable containing packages to install.
    '''
    log_current_packages(packages)
    return _run_shell_command_raise_on_return_code('sudo dnf install -y {}'.format(' '.join(packages)), 'Error in installation of package(s) {}'.format(' '.join(packages)), True)


def dnf_remove_packages(*packages: str):
    '''
    Remove packages from Fedora / RedHat / Cent systems.

    :param packages: Iterable containing packages to remove.
    '''
    log_current_packages(packages, install=False)
    return _run_shell_command_raise_on_return_code('sudo dnf remove -y {}'.format(' '.join(packages)), 'Error in removal of package(s) {}'.format(' '.join(packages)), True)


def apt_update_sources():
    '''
    Update package lists on Ubuntu / Debian / Mint / Kali systems.
    '''
    return _run_shell_command_raise_on_return_code('sudo apt-get update', 'Unable to update repository sources. Check network.')


def apt_install_packages(*packages: str):
    '''
    Install packages on Ubuntu / Debian / Mint / Kali systems.

    :param packages: Iterable containing packages to install.
    '''
    log_current_packages(packages)
    return _run_shell_command_raise_on_return_code('sudo apt-get install -y {}'.format(' '.join(packages)), 'Error in installation of package(s) {}'.format(' '.join(packages)), True)


def apt_remove_packages(*packages: str):
    '''
    Remove packages from Ubuntu / Debian / Mint / Kali systems.

    :param packages: Iterable containing packages to remove.
    '''
    log_current_packages(packages, install=False)
    return _run_shell_command_raise_on_return_code('sudo apt-get remove -y {}'.format(' '.join(packages)), 'Error in removal of package(s) {}'.format(' '.join(packages)), True)


def check_if_command_in_path(command: str) -> bool:
    '''
    Check if a given command is executable on the current system, i.e. found in systems PATH.
    Useful to find out if a program is already installed.

    :param command: Command to check.
    '''
    _, return_code = execute_shell_command_get_return_code('command -v {}'.format(command))
    if return_code != 0:
        return False
    return True


def check_string_in_command_output(command: str, target_string: str) -> bool:
    '''
    Execute command and test if string is contained in its output (i.e. stdout).

    :param command: Command to execute.
    :param target_string: String to match on output.
    :return: `True` if string was found and return code was 0, else `False`.
    '''
    output, return_code = execute_shell_command_get_return_code(command)
    return return_code == 0 and target_string in output


def install_github_project(project_path: str, commands: List[str]):
    '''
    Install github project by cloning it, running a set of commands and removing the cloned files afterwards.

    :param project_path: Github path to project. For FACT this is 'fkie-cad/FACT_core'.
    :param commands: List of commands to run after cloning to install project.

    :Example:

        .. code-block:: python

            install_github_project(
                'ghusername/c-style-project',
                ['./configure', 'make', 'sudo make install']
            )
    '''
    log_current_packages((project_path, ))
    folder_name = Path(project_path).name
    _checkout_github_project(project_path, folder_name)

    with OperateInDirectory(folder_name, remove=True):
        error = None
        for command in commands:
            output, return_code = execute_shell_command_get_return_code(command)
            if return_code != 0:
                error = 'Error while processing github project {}!\n{}'.format(project_path, output)
                break

    if error:
        raise InstallationError(error)


def _checkout_github_project(github_path: str, folder_name: str):
    clone_url = 'https://www.github.com/{}'.format(github_path)
    _, return_code = execute_shell_command_get_return_code('git clone {}'.format(clone_url))
    if return_code != 0:
        raise InstallationError('Cloning from github failed for project {}\n {}'.format(github_path, clone_url))
    if not Path('.', folder_name).exists():
        raise InstallationError('Repository creation failed on folder {}\n {}'.format(folder_name, clone_url))


def load_main_config() -> configparser.ConfigParser:
    '''
    Create config object from main.cfg in src/config folder.

    :return: config object.
    '''
    config = configparser.ConfigParser()
    config_path = Path(Path(__file__).parent.parent, 'config', 'main.cfg')
    if not config_path.is_file():
        raise InstallationError('Could not load config at path {}'.format(config_path))
    config.read(str(config_path))
    return config
