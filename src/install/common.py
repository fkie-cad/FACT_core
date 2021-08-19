import logging
from contextlib import suppress
from pathlib import Path

from common_helper_process import execute_shell_command_get_return_code

from helperFunctions.install import (
    InstallationError, OperateInDirectory, apt_install_packages, apt_update_sources, dnf_install_packages,
    dnf_update_sources, install_github_project, read_package_list_from_file, run_cmd_with_logging
)

BIN_DIR = Path(__file__).parent.parent / 'bin'
INSTALL_DIR = Path(__file__).parent


def install_pip(python_command):
    logging.info('Installing {} pip'.format(python_command))
    for command in ['wget https://bootstrap.pypa.io/get-pip.py', 'sudo -EH {} get-pip.py'.format(python_command), 'rm get-pip.py']:
        output, return_code = execute_shell_command_get_return_code(command)
        if return_code != 0:
            raise InstallationError('Error in pip installation for {}:\n{}'.format(python_command, output))


def main(distribution):  # pylint: disable=too-many-statements
    _update_package_sources(distribution)

    apt_packages_path = INSTALL_DIR / "apt-pkgs-common.txt"
    dnf_packages_path = INSTALL_DIR / "dnf-pkgs-common.txt"

    if distribution != "fedora":
        pkgs = read_package_list_from_file(apt_packages_path)
        apt_install_packages(*pkgs)
    else:
        pkgs = read_package_list_from_file(dnf_packages_path)
        dnf_install_packages(*pkgs)

    run_cmd_with_logging("sudo -EH pip3 install -r ./requirements_common.txt")

    _, is_repository = execute_shell_command_get_return_code('git status')
    if is_repository == 0:
        # update submodules
        git_output, git_code = execute_shell_command_get_return_code('(cd ../../ && git submodule foreach "git pull")')
        if git_code != 0:
            raise InstallationError('Failed to update submodules\n{}'.format(git_output))
    else:
        logging.warning('FACT is not set up using git. Note that *adding submodules* won\'t work!!')

    # make bin dir
    BIN_DIR.mkdir(exist_ok=True)

    install_pip('python3')

    # VarietyJS (is executed by update_statistic.py)
    if (BIN_DIR / 'spec').exists():
        logging.warning('variety spec not overwritten')
    else:
        install_github_project('variety/variety', ['git checkout 2f4d815', 'mv -f variety.js ../../bin', 'mv -f spec ../../bin'])

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_all_installed_fact_components').unlink()
        Path('start_all_installed_fact_components').symlink_to('src/start_fact.py')

    return 0


def _update_package_sources(distribution):
    logging.info('Updating system')
    if distribution == 'fedora':
        dnf_update_sources()
    else:
        apt_update_sources()
