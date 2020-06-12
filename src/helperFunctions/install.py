import configparser
import logging
import os
import shutil
from pathlib import Path
from typing import List, Union

from common_helper_process import execute_shell_command_get_return_code


class InstallationError(Exception):
    pass


class OperateInDirectory:
    def __init__(self, target_directory: Union[str, Path], remove=False):
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


def remove_folder(folder_name):
    try:
        shutil.rmtree(folder_name)
    except PermissionError:
        logging.debug('Falling back on root permission for deleting {}'.format(folder_name))
        execute_shell_command_get_return_code('sudo rm -rf {}'.format(folder_name))
    except Exception as exception:
        raise InstallationError(exception)


def log_current_packages(packages, install=True):
    action = 'Installing' if install else 'Removing'
    logging.info('{} {}'.format(action, ' '.join(packages)))


def run_shell_command_raise_on_return_code(command: str, error: str, add_output_on_error=False) -> str:  # pylint: disable=invalid-name
    output, return_code = execute_shell_command_get_return_code(command)
    if return_code != 0:
        if add_output_on_error:
            error = '{}\n{}'.format(error, output)
        raise InstallationError(error)
    return output


def apt_update_sources():
    return run_shell_command_raise_on_return_code('sudo apt-get update', 'Unable to update repository sources. Check network.')


def apt_install_packages(*args):
    log_current_packages(args)
    return run_shell_command_raise_on_return_code('sudo apt-get install -y {}'.format(' '.join(args)), 'Error in installation of package(s) {}'.format(' '.join(args)), True)


def apt_remove_packages(*args):
    log_current_packages(args, install=False)
    return run_shell_command_raise_on_return_code('sudo apt-get remove -y {}'.format(' '.join(args)), 'Error in removal of package(s) {}'.format(' '.join(args)), True)


def _pip_install_packages(version, args):
    log_current_packages(args)
    for packet in args:
        try:
            run_shell_command_raise_on_return_code('sudo -EH pip{} install --upgrade {}'.format(version, packet), 'Error in installation of python package {}'.format(packet), True)
        except InstallationError as installation_error:
            if 'is a distutils installed project' in str(installation_error):
                logging.warning('Could not update python packet {}. Was not installed using pip originally'.format(packet))
            else:
                raise installation_error


def _pip_remove_packages(version, args):
    log_current_packages(args, install=False)
    for packet in args:
        try:
            run_shell_command_raise_on_return_code('sudo -EH pip{} uninstall {}'.format(version, packet),
                                                   'Error in removal of python package {}'.format(packet), True)
        except InstallationError as installation_error:
            if 'is a distutils installed project' in str(installation_error):
                logging.warning('Could not remove python packet {}. Was not installed using pip originally'.format(packet))
            else:
                raise installation_error


def pip3_install_packages(*args):
    return _pip_install_packages(3, args)


def pip3_remove_packages(*args):
    return _pip_remove_packages(3, args)


def pip2_install_packages(*args):
    return _pip_install_packages(2, args)


def pip2_remove_packages(*args):
    return _pip_remove_packages(2, args)


def check_if_command_in_path(command):
    _, return_code = execute_shell_command_get_return_code('command -v {}'.format(command))
    if return_code != 0:
        return False
    return True


def check_string_in_command(command, target_string):
    output, return_code = execute_shell_command_get_return_code(command)
    return return_code == 0 and target_string in output


def install_github_project(project_path: str, commands: List[str]):
    log_current_packages([project_path, ])
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


def _checkout_github_project(github_path, folder_name):
    clone_url = 'https://www.github.com/{}'.format(github_path)
    _, return_code = execute_shell_command_get_return_code('git clone {}'.format(clone_url))
    if return_code != 0:
        raise InstallationError('Cloning from github failed for project {}\n {}'.format(github_path, clone_url))
    if not Path('.', folder_name).exists():
        raise InstallationError('Repository creation failed on folder {}\n {}'.format(folder_name, clone_url))


def load_main_config():
    config = configparser.ConfigParser()
    config_path = Path(Path(__file__).parent.parent, 'config', 'main.cfg')
    if not config_path.is_file():
        raise InstallationError('Could not load config at path {}'.format(config_path))
    config.read(str(config_path))
    return config
