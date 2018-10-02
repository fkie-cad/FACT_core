import os
from pathlib import Path
from typing import List

from common_helper_process import execute_shell_command_get_return_code


class InstallationError(Exception):
    pass


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
    output, return_code = execute_shell_command_get_return_code('sudo apt-get install -y {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in installation of package(s) {}\n{}'.format(' '.join(args), output))
    return output


def apt_remove_packages(*args):
    output, return_code = execute_shell_command_get_return_code('sudo apt-get remove -y {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in removal of package(s) {}\n{}'.format(' '.join(args), output))
    return output


def pip_install_packages(*args):
    output, return_code = execute_shell_command_get_return_code('sudo -EH pip3 install --upgrade {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in installation of python package(s) {}\n{}'.format(' '.join(args), output))
    return output


def pip_remove_packages(*args):
    pass


def check_if_command_in_path(command_with_parameters):
    pass


def check_if_executable_in_bin_folder(executable_name):
    pass


def install_github_project(project_path: str, commands: List[str]):
    folder_name = Path(project_path).name
    _checkout_github_project(project_path, folder_name)
    for command in commands:
        output, return_code = execute_shell_command_get_return_code(command)
        if return_code != 0:
            raise InstallationError('Error while processing github project {}!\n{}'.format(project_path, output))
    _remove_repo_folder(project_path)


def _checkout_github_project(github_path, folder_name):
    clone_url = 'https://www.github.com/{}'.format(github_path)
    output, return_code = execute_shell_command_get_return_code('git clone {}'.format(clone_url))
    if return_code != 0:
        raise InstallationError('Cloning from github failed for project {}\n {}'.format(github_path, clone_url))
    if not Path('.', folder_name).exists():
        raise InstallationError('Repository creation failed on folder {}\n {}'.format(folder_name, clone_url))
    os.chdir(folder_name)


def _remove_repo_folder(folder_name):
    try:
        os.chdir('..')
        Path(folder_name).unlink()
    except Exception as exception:
        raise InstallationError(exception)
