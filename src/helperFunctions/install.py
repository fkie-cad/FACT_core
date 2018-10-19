import configparser
import logging
import os
import shutil
from pathlib import Path
from typing import List

from common_helper_process import execute_shell_command_get_return_code


class InstallationError(Exception):
    pass


class OperateInDirectory():
    def __init__(self, target_directory, remove=False):
        self._current_working_dir = None
        self._target_directory = target_directory
        self._remove = remove

    def __enter__(self):
        self._current_working_dir = os.getcwd()
        os.chdir(self._target_directory)

    def __exit__(self, *args):
        os.chdir(self._current_working_dir)
        if self._remove:
            shutil.rmtree(self._target_directory)


def log_current_packages(packages, install=True):
    action = 'Installing' if install else 'Removing'
    logging.info('{} {}'.format(action, ' '.join(packages)))


def apt_update_sources():
    output, return_code = execute_shell_command_get_return_code('sudo apt-get update')
    if return_code != 0:
        raise InstallationError('Unable to update repository sources. Check network.')
    return output


def apt_upgrade_system():
    output, return_code = execute_shell_command_get_return_code('sudo apt-get upgrade -y')
    if return_code != 0:
        raise InstallationError('Unable to upgrade packages: \n{}'.format(output))
    return output


def apt_autoremove_packages():
    output, return_code = execute_shell_command_get_return_code('sudo apt-get autoremove -y')
    if return_code != 0:
        raise InstallationError('Automatic removal of packages failed:\n{}'.format(output))
    return output


def apt_clean_system():
    output, return_code = execute_shell_command_get_return_code('sudo apt-get clean')
    if return_code != 0:
        raise InstallationError('Cleaning of package files failed:\n{}'.format(output))
    return output


def apt_install_packages(*args):
    log_current_packages(args)
    output, return_code = execute_shell_command_get_return_code('sudo apt-get install -y {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in installation of package(s) {}\n{}'.format(' '.join(args), output))
    return output


def apt_remove_packages(*args):
    log_current_packages(args, install=False)
    output, return_code = execute_shell_command_get_return_code('sudo apt-get remove -y {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in removal of package(s) {}\n{}'.format(' '.join(args), output))
    return output


def pip_install_packages(*args):
    log_current_packages(args)
    output, return_code = execute_shell_command_get_return_code('sudo -EH pip3 install --upgrade {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in installation of python package(s) {}\n{}'.format(' '.join(args), output))
    return output


def pip_remove_packages(*args):
    log_current_packages(args, install=False)
    output, return_code = execute_shell_command_get_return_code('sudo -EH pip3 uninstall {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in removal of python package(s) {}\n{}'.format(' '.join(args), output))
    return output


def pip2_install_packages(*args):
    log_current_packages(args)
    output, return_code = execute_shell_command_get_return_code('sudo -EH pip2 install --upgrade {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in installation of python package(s) {}\n{}'.format(' '.join(args), output))
    return output


def pip2_remove_packages(*args):
    log_current_packages(args, install=False)
    output, return_code = execute_shell_command_get_return_code('sudo -EH pip2 uninstall {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in removal of python package(s) {}\n{}'.format(' '.join(args), output))
    return output


def check_if_command_in_path(command):
    output, return_code = execute_shell_command_get_return_code('command -v {}'.format(command))
    if return_code != 0:
        return False
    return True


def check_if_executable_in_bin_folder(executable_name):
    pass


def check_string_in_command(command, target_string):
    output, return_code = execute_shell_command_get_return_code(command)
    if return_code != 0 or target_string not in output:
        return False
    return True


def install_github_project(project_path: str, commands: List[str]):
    log_current_packages([project_path, ])
    folder_name = Path(project_path).name
    _checkout_github_project(project_path, folder_name)

    error = None
    for command in commands:
        output, return_code = execute_shell_command_get_return_code(command)
        if return_code != 0:
            error = InstallationError('Error while processing github project {}!\n{}'.format(project_path, output))
            break

    _remove_repo_folder(folder_name)
    if error:
        raise error


def _checkout_github_project(github_path, folder_name):
    clone_url = 'https://www.github.com/{}'.format(github_path)
    output, return_code = execute_shell_command_get_return_code('git clone {}'.format(clone_url))
    if return_code != 0:
        raise InstallationError('Cloning from github failed for project {}\n {}'.format(github_path, clone_url))
    if not Path('.', folder_name).exists():
        raise InstallationError('Repository creation failed on folder {}\n {}'.format(folder_name, clone_url))
    os.chdir(folder_name)


# TODO Combine with OperateInDirectory
def _remove_repo_folder(folder_name):
    try:
        os.chdir('..')
        shutil.rmtree(folder_name)
    except PermissionError:
        logging.debug('Falling back on root permission for deleting {}'.format(folder_name))
        execute_shell_command_get_return_code('sudo rm -rf {}'.format(folder_name))
    except Exception as exception:
        raise InstallationError(exception)


def load_main_config():
    config = configparser.ConfigParser()
    config_path = Path('..', 'config', 'main.cfg')
    if not config_path.is_file():
        raise InstallationError('Could not load config at path {}'.format(config_path))
    config.read(str(config_path))
    return config
