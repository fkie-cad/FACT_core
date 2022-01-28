import logging
import subprocess
from contextlib import suppress
from pathlib import Path
from platform import python_version_tuple

from subprocess import PIPE, STDOUT
from pkg_resources import parse_version

from helperFunctions.install import (
    InstallationError, OperateInDirectory, apt_install_packages, apt_update_sources, dnf_install_packages,
    dnf_update_sources, install_github_project, install_pip_packages, is_virtualenv, read_package_list_from_file,
    run_cmd_with_logging
)

BIN_DIR = Path(__file__).parent.parent / 'bin'
INSTALL_DIR = Path(__file__).parent
PIP_DEPENDENCIES = INSTALL_DIR / 'requirements_common.txt'


def install_pip():
    python_version = '.'.join(python_version_tuple()[:2])
    if parse_version(python_version) < parse_version('3.7'):
        logging.warning('Your Python version is outdated. Please upgrade it.')
        pip_link = f'https://bootstrap.pypa.io/pip/{python_version}/get-pip.py'
    else:
        pip_link = 'https://bootstrap.pypa.io/get-pip.py'

    logging.info('Installing python3 pip')
    for command in [f'wget {pip_link}', 'sudo -EH python3 get-pip.py', 'rm get-pip.py']:
        cmd_p = subprocess.run(command, shell=True, stdout=PIPE, stderr=STDOUT, text=True)
        if cmd_p.returncode != 0:
            raise InstallationError(f'Error in pip installation for python3:\n{cmd_p.stdout}')


def main(distribution):  # pylint: disable=too-many-statements
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

    # VarietyJS (is executed by update_statistic.py)
    if (BIN_DIR / 'spec').exists():
        logging.warning('variety spec not overwritten')
    else:
        install_github_project('variety/variety', ['git checkout 2f4d815', 'mv -f variety.js ../../bin/', 'mv -f spec ../../bin/'])

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_all_installed_fact_components').unlink()
        Path('start_all_installed_fact_components').symlink_to('src/start_fact.py')

    return 0


def _update_submodules():
    git_p = subprocess.run('git status', shell=True, stdout=PIPE, stderr=STDOUT, text=True)
    if git_p.returncode == 0:
        git_submodule_p = subprocess.run('(cd ../../ && git submodule foreach "git pull")', shell=True, stdout=PIPE, stderr=STDOUT, text=True)
        if git_submodule_p.returncode != 0:
            raise InstallationError(f'Failed to update submodules\n{git_submodule_p.stdout}')
    else:
        logging.warning('FACT is not set up using git. Note that *adding submodules* won\'t work!!')


def _update_package_sources(distribution):
    logging.info('Updating system')
    if distribution == 'fedora':
        dnf_update_sources()
    else:
        apt_update_sources()
