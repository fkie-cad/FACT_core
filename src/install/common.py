import logging
import os
from contextlib import suppress
from pathlib import Path

from common_helper_process import execute_shell_command_get_return_code

from helperFunctions.install import (
    InstallationError, OperateInDirectory, apt_autoremove_packages, apt_clean_system, apt_install_packages,
    apt_remove_packages, apt_update_sources, apt_upgrade_system, install_github_project, pip3_install_packages
)


def install_pip(python_command):
    logging.info('Installing {} pip'.format(python_command))
    for command in ['wget https://bootstrap.pypa.io/get-pip.py', 'sudo -EH {} get-pip.py'.format(python_command), 'rm get-pip.py']:
        output, return_code = execute_shell_command_get_return_code(command)
        if return_code != 0:
            raise InstallationError('Error in pip installation for {}:\n{}'.format(python_command, output))


def main(distribution):  # pylint: disable=too-many-statements
    apt_install_packages('apt-transport-https')

    logging.info('Updating system')
    apt_update_sources()
    apt_upgrade_system()
    apt_autoremove_packages()
    apt_clean_system()

    _, is_repository = execute_shell_command_get_return_code('git status')
    if is_repository == 0:
        # update submodules
        git_output, git_code = execute_shell_command_get_return_code('(cd ../../ && git submodule foreach "git pull")')
        if git_code != 0:
            raise InstallationError('Failed to update submodules\n{}'.format(git_output))
    else:
        logging.warning('FACT is not set up using git. Note that *adding submodules* won\'t work!!')

    # make bin dir
    with suppress(FileExistsError):
        os.mkdir('../bin')

    # install python3 and general build stuff
    apt_install_packages('python3', 'python3-dev', 'build-essential', 'automake', 'autoconf', 'libtool', 'git', 'unzip')
    if not distribution == 'xenial':
        pip3_install_packages('testresources')

    # get a bugfree recent pip version
    apt_remove_packages('python3-pip', 'python3-setuptools', 'python3-wheel')
    apt_autoremove_packages()
    install_pip('python3')

    # install python2
    apt_install_packages('python', 'python-dev')
    apt_remove_packages('python-pip')
    apt_autoremove_packages()
    install_pip('python2')

    # install general python dependencys
    apt_install_packages('libmagic-dev')
    apt_install_packages('libfuzzy-dev')
    apt_install_packages('python3-tlsh')
    pip3_install_packages('git+https://github.com/fkie-cad/fact_helper_file.git')
    pip3_install_packages('psutil')
    pip3_install_packages('pytest==3.5.1', 'pytest-cov', 'pytest-flake8', 'pylint', 'python-magic', 'xmltodict', 'yara-python==3.7.0', 'appdirs')
    pip3_install_packages('ssdeep')
    pip3_install_packages('lief')
    pip3_install_packages('requests')

    # install python mongo bindings
    pip3_install_packages('pymongo', 'pyyaml')

    # VarietyJS (is executed by update_statistic.py)
    try:
        install_github_project('variety/variety', ['git checkout 2f4d815', 'mv -f variety.js ../../bin', 'mv -f spec ../../bin'])
    except InstallationError as installation_error:
        if 'Directory not empty' not in str(installation_error):
            raise installation_error
        logging.warning('variety spec not overwritten')

    #  installing common code modules
    pip3_install_packages('hurry.filesize')
    pip3_install_packages('git+https://github.com/fkie-cad/common_helper_files.git')
    pip3_install_packages('git+https://github.com/fkie-cad/common_helper_mongo.git')
    pip3_install_packages('git+https://github.com/mass-project/common_helper_encoder.git')
    pip3_install_packages('git+https://github.com/fkie-cad/common_helper_filter.git')
    pip3_install_packages('git+https://github.com/fkie-cad/common_helper_process.git')

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_all_installed_fact_components').unlink()
        Path('start_all_installed_fact_components').symlink_to('src/start_fact.py')

    return 0
