from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from subprocess import DEVNULL, PIPE, STDOUT, CalledProcessError

import distro


class InstallationError(Exception):
    """
    Class representing all expected errors that happen during installation, such as timeouts on remote hosts.
    """


class OperateInDirectory:
    """
    Context manager allowing to execute a number of commands in a given directory. On exit, the working directory is
    changed back to its previous value.

    :param target_directory: Directory path to use as working directory.
    :param remove: Optional boolean to indicate if `target_directory` should be removed on exit.
    """

    def __init__(self, target_directory: str | Path, remove: bool = False):
        self._current_working_dir = None
        self._target_directory = str(target_directory)
        self._remove = remove

    def __enter__(self):
        self._current_working_dir = os.getcwd()  # noqa: PTH109
        os.chdir(self._target_directory)

    def __exit__(self, *args):
        os.chdir(self._current_working_dir)
        if self._remove:
            remove_folder(self._target_directory)


def remove_folder(folder_name: str):
    """
    Python equivalent to `rm -rf`. Remove a directory an all included files. If administrative rights are necessary,
    this effectively falls back to `sudo rm -rf`.

    :param folder_name: Path to directory to remove.
    """
    try:
        shutil.rmtree(folder_name)
    except PermissionError:
        logging.debug(f'Falling back on root permission for deleting {folder_name}')
        subprocess.run(f'sudo rm -rf {folder_name}', shell=True, check=False)
    except Exception as exception:
        raise InstallationError(exception) from None


def log_current_packages(packages: tuple[str], install: bool = True):
    """
    Log which packages are installed or removed.

    :param packages: List of packages that are affected.
    :param install: Identifier to distinguish installation from removal.
    """
    action = 'Installing' if install else 'Removing'
    logging.info(f"{action} {' '.join(packages)}")


def _run_shell_command_raise_on_return_code(command: str, error: str, add_output_on_error=False) -> str:
    cmd_process = subprocess.run(command, shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False)
    if cmd_process.returncode != 0:
        if add_output_on_error:
            error = f'{error}\n{cmd_process.stdout}'
        raise InstallationError(error)
    return cmd_process.stdout


def dnf_update_sources():
    """
    Update package lists on Fedora / RedHat / Cent systems.
    """
    return _run_shell_command_raise_on_return_code('sudo dnf update -y', 'Unable to update')


def dnf_install_packages(*packages: str):
    """
    Install packages on Fedora / RedHat / Cent systems.

    :param packages: Iterable containing packages to install.
    """
    log_current_packages(packages)
    return _run_shell_command_raise_on_return_code(
        f"sudo dnf install -y {' '.join(packages)}", f"Error in installation of package(s) {' '.join(packages)}", True
    )


def dnf_remove_packages(*packages: str):
    """
    Remove packages from Fedora / RedHat / Cent systems.

    :param packages: Iterable containing packages to remove.
    """
    log_current_packages(packages, install=False)
    return _run_shell_command_raise_on_return_code(
        f"sudo dnf remove -y {' '.join(packages)}", f"Error in removal of package(s) {' '.join(packages)}", True
    )


def apt_update_sources():
    """
    Update package lists on Ubuntu / Debian / Mint / Kali systems.
    """
    return _run_shell_command_raise_on_return_code(
        'sudo apt-get update', 'Unable to update repository sources. Check network.'
    )


def apt_install_packages(*packages: str):
    """
    Install packages on Ubuntu / Debian / Mint / Kali systems.

    :param packages: Iterable containing packages to install.
    """
    log_current_packages(packages)
    return _run_shell_command_raise_on_return_code(
        f"sudo apt-get install -y {' '.join(packages)}",
        f"Error in installation of package(s) {' '.join(packages)}",
        True,
    )


def apt_remove_packages(*packages: str):
    """
    Remove packages from Ubuntu / Debian / Mint / Kali systems.

    :param packages: Iterable containing packages to remove.
    """
    log_current_packages(packages, install=False)
    return _run_shell_command_raise_on_return_code(
        f"sudo apt-get remove -y {' '.join(packages)}", f"Error in removal of package(s) {' '.join(packages)}", True
    )


def check_if_command_in_path(command: str) -> bool:
    """
    Check if a given command is executable on the current system, i.e. found in systems PATH.
    Useful to find out if a program is already installed.

    :param command: Command to check.
    """
    command_process = subprocess.run(
        f'command -v {command}', shell=True, stdout=DEVNULL, stderr=DEVNULL, text=True, check=False
    )
    return command_process.returncode == 0


def install_github_project(project_path: str, commands: list[str]):
    """
    Install github project by cloning it, running a set of commands and removing the cloned files afterwards.

    :param project_path: Github path to project. For FACT this is 'fkie-cad/FACT_core'.
    :param commands: List of commands to run after cloning to install project.

    :Example:

        .. code-block:: python

            install_github_project(
                'ghusername/c-style-project',
                ['./configure', 'make', 'sudo make install']
            )
    """
    log_current_packages((project_path,))
    folder_name = Path(project_path).name
    _checkout_github_project(project_path, folder_name)

    with OperateInDirectory(folder_name, remove=True):
        error = None
        for command in commands:
            cmd_process = subprocess.run(command, shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False)
            if cmd_process.returncode != 0:
                error = f'Error while processing github project {project_path}!\n{cmd_process.stdout}'
                break

    if error:
        raise InstallationError(error)


def _checkout_github_project(github_path: str, folder_name: str):
    clone_url = f'https://www.github.com/{github_path}'
    git_process = subprocess.run(
        f'git clone {clone_url}', shell=True, stdout=DEVNULL, stderr=DEVNULL, text=True, check=False
    )
    if git_process.returncode != 0:
        raise InstallationError(f'Cloning from github failed for project {github_path}\n {clone_url}')
    if not Path('.', folder_name).exists():
        raise InstallationError(f'Repository creation failed on folder {folder_name}\n {clone_url}')


def run_cmd_with_logging(cmd: str, raise_error=True, shell=False, silent: bool = False, **kwargs):
    """
    Runs `cmd` with subprocess.run, logs the command it executes and logs
    stderr on non-zero returncode.
    All keyword arguments are except `raise_error` passed to subprocess.run.

    :param shell: execute the command through the shell.
    :param raise_error: Whether or not an error should be raised when `cmd` fails
    :param silent: don't log in case of error.
    """
    logging.debug(f'Running: {cmd}')
    try:
        cmd_ = cmd if shell else shlex.split(cmd)
        subprocess.run(cmd_, stdout=PIPE, stderr=STDOUT, encoding='UTF-8', shell=shell, check=True, **kwargs)
    except CalledProcessError as err:
        if not silent:
            logging.log(logging.ERROR if raise_error else logging.DEBUG, f'Failed to run {cmd}:\n{err.stdout}')
        if raise_error:
            raise err


def check_distribution(allow_unsupported=False):
    """
    Check if the distribution is supported by the installer.

    :return: The codename of the distribution
    """
    debian_code_names = ['buster', 'stretch', 'bullseye', 'bookworm', 'kali-rolling']
    focal_code_names = ['focal', 'ulyana', 'ulyssa', 'uma', 'una']
    jammy_code_names = ['jammy', 'vanessa', 'vera', 'victoria', 'virginia']
    noble_code_names = ['noble', 'wilma', 'xia', 'zara']

    codename = distro.codename().lower()
    if codename in focal_code_names:
        logging.debug('Ubuntu 20.04 detected')
        return 'focal'
    if codename in jammy_code_names:
        logging.debug('Ubuntu 22.04 detected')
        return 'jammy'
    if codename in noble_code_names:
        logging.debug('Ubuntu 24.04 detected')
        return 'noble'
    if codename in debian_code_names:
        logging.debug('Debian/Kali detected')
        return codename
    if distro.id() == 'fedora':
        logging.debug('Fedora detected')
        return 'fedora'
    msg = (
        f'Your Distribution ({distro.id()} {distro.version()}) is not supported. '
        'FACT Installer requires Ubuntu 20.04/22.04/24.04, Debian 11/12 or compatible!'
    )
    if allow_unsupported:
        logging.info(msg)
        return None
    logging.critical(msg)
    sys.exit(1)


def install_pip_packages(package_file: Path):
    """
    Install or upgrade python packages from file `package_file` using pip. Does not raise an error if the installation
    fails because the package is already installed through the system's package manager. The package file should
    have one package per line (empty lines and comments are allowed).

    :param package_file: The path to the package file.
    """
    for package in read_package_list_from_file(package_file):
        try:
            install_single_pip_package(package)
        except CalledProcessError as error:
            # don't fail if a package is already installed using apt and can't be upgraded
            if error.stdout is not None and 'distutils installed' in error.stdout:
                logging.warning(
                    f'Pip package {package} is already installed with distutils. '
                    f'This may Cause problems:\n{error.stdout}'
                )
                continue
            logging.error(f'Pip package {package} could not be installed:\n{error.stderr or error.stdout}')
            raise


def install_single_pip_package(package: str):
    command = f'pip3 install -U {package} --prefer-binary'  # prefer binary release to compiling latest
    if not is_virtualenv():
        command = 'sudo -EH ' + command
    run_cmd_with_logging(command, silent=True)


def read_package_list_from_file(path: Path):
    """
    Reads the file at `path` into a list.
    Each line in the file should be either a comment (starts with #) or a
    package name.
    There may not be multiple packages in one line.

    :param path: The path to the file.
    :return: A list of package names contained in the file.
    """
    packages = []
    for line_ in path.read_text().splitlines():
        line = line_.strip(' \t')
        # Skip comments and empty lines
        if line.startswith('#') or len(line) == 0:
            continue
        packages.append(line)

    return packages


def is_virtualenv() -> bool:
    """Check if FACT runs in a virtual environment"""
    return sys.prefix != getattr(sys, 'base_prefix', getattr(sys, 'real_prefix', None))
