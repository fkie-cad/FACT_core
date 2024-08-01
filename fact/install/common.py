import logging
import subprocess
from contextlib import suppress
from pathlib import Path
from platform import python_version_tuple
from subprocess import PIPE, STDOUT

from pkg_resources import parse_version

from helperFunctions.install import (
    InstallationError,
    OperateInDirectory,
    apt_install_packages,
    apt_update_sources,
    dnf_install_packages,
    dnf_update_sources,
    install_pip_packages,
    is_virtualenv,
    read_package_list_from_file,
    run_cmd_with_logging,
)

BIN_DIR = Path(__file__).parent.parent / 'bin'
INSTALL_DIR = Path(__file__).parent
PIP_DEPENDENCIES = INSTALL_DIR / 'requirements_common.txt'


def install_pip():
    python_version = '.'.join(python_version_tuple()[:2])
    if parse_version(python_version) < parse_version('3.8'):
        logging.warning('Your Python version is outdated. Please upgrade it.')
        pip_link = f'https://bootstrap.pypa.io/pip/{python_version}/get-pip.py'
    else:
        pip_link = 'https://bootstrap.pypa.io/get-pip.py'

    logging.info('Installing python3 pip')
    for command in [f'wget {pip_link}', 'sudo -EH python3 get-pip.py', 'rm get-pip.py']:
        cmd_process = subprocess.run(command, shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False)
        if cmd_process.returncode != 0:
            raise InstallationError(f'Error in pip installation for python3:\n{cmd_process.stdout}')


def main(distribution):
    _update_package_sources(distribution)
    _update_submodules()

    BIN_DIR.mkdir(exist_ok=True)

    apt_packages_path = INSTALL_DIR / 'apt-pkgs-common.txt'
    dnf_packages_path = INSTALL_DIR / 'dnf-pkgs-common.txt'

    if distribution != 'fedora':
        pkgs = read_package_list_from_file(apt_packages_path)
        apt_install_packages(*pkgs)
    else:
        pkgs = read_package_list_from_file(dnf_packages_path)
        dnf_install_packages(*pkgs)

    if not is_virtualenv():
        install_pip()
    elif distribution != 'fedora':
        run_cmd_with_logging('pip install -U pip setuptools wheel')
    else:
        # on fedora, extra setuptools will break some system tools like selinux ones
        run_cmd_with_logging('pip install -U pip wheel')
    install_pip_packages(PIP_DEPENDENCIES)

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_all_installed_fact_components').unlink()
        Path('start_all_installed_fact_components').symlink_to('src/start_fact.py')

    return 0


def _update_submodules():
    git_process = subprocess.run('git status', shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False)
    if git_process.returncode == 0:
        git_submodule_process = subprocess.run(
            '(cd ../../ && git submodule foreach "git pull")',
            shell=True,
            stdout=PIPE,
            stderr=STDOUT,
            text=True,
            check=False,
        )
        if git_submodule_process.returncode != 0:
            raise InstallationError(f'Failed to update submodules\n{git_submodule_process.stdout}')
    else:
        logging.warning("FACT is not set up using git. Note that *adding submodules* won't work!!")


def _update_package_sources(distribution):
    logging.info('Updating system')
    if distribution == 'fedora':
        dnf_update_sources()
    else:
        apt_update_sources()
