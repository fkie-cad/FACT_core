import logging
from contextlib import suppress
from pathlib import Path

from common_helper_process import execute_shell_command_get_return_code

from helperFunctions.install import (
    InstallationError, OperateInDirectory, apt_install_packages, apt_remove_packages, apt_update_sources,
    dnf_install_packages, dnf_remove_packages, dnf_update_sources, install_github_project, pip3_install_packages
)

BIN_DIR = Path(__file__).parent.parent / 'bin'


def install_pip(python_command):
    logging.info('Installing {} pip'.format(python_command))
    for command in ['proxychains wgethttps://bootstrap.pypa.io/get-pip.py', 'sudo -EH {} get-pip.py'.format(python_command), 'rm get-pip.py']:
        output, return_code = execute_shell_command_get_return_code(command)
        if return_code != 0:
            raise InstallationError('Error in pip installation for {}:\n{}'.format(python_command, output))


def main(distribution):  # pylint: disable=too-many-statements

    _update_package_sources(distribution)

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

    # install python3 and general build stuff
    if distribution == 'fedora':
        dnf_install_packages('python3', 'python3-devel', 'automake', 'autoconf', 'libtool', 'git', 'unzip')
        # build-essential not available on fedora, getting equivalent
        dnf_install_packages('gcc', 'gcc-c++', 'make', 'kernel-devel')
    else:
        apt_install_packages('python3', 'python3-dev', 'build-essential', 'automake', 'autoconf', 'libtool', 'git', 'unzip')
        pip3_install_packages('testresources')

    # get a bug free recent pip version
    if distribution == 'fedora':
        dnf_remove_packages('python3-pip', 'python3-setuptools', 'python3-wheel')
    else:
        apt_remove_packages('python3-pip', 'python3-setuptools', 'python3-wheel')

    install_pip('python3')
    pip3_install_packages('setuptools')

    # install general python dependencies
    if distribution == 'fedora':
        dnf_install_packages('file-devel')
        dnf_install_packages('libffi-devel')
        dnf_install_packages('python3-tlsh')
        dnf_install_packages('python3-ssdeep')
    else:
        apt_install_packages('libmagic-dev')
        apt_install_packages('libfuzzy-dev')
        apt_install_packages('python3-tlsh')
        pip3_install_packages('ssdeep')

    pip3_install_packages('git+https://github.com/fkie-cad/fact_helper_file.git')
    pip3_install_packages('psutil', 'pytest', 'pytest-cov', 'pylint', 'python-magic', 'xmltodict', 'yara-python==3.7.0', 'appdirs', 'flaky')

    pip3_install_packages('lief==0.10.1')  # FIXME: unpin version when install bug is fixed

    pip3_install_packages('requests')

    # install python MongoDB bindings
    pip3_install_packages('pymongo', 'pyyaml')

    # VarietyJS (is executed by update_statistic.py)
    if (BIN_DIR / 'spec').exists():
        logging.warning('variety spec not overwritten')
    else:
        install_github_project('variety/variety', ['git checkout 2f4d815', 'mv -f variety.js ../../bin', 'mv -f spec ../../bin'])

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


def _update_package_sources(distribution):
    logging.info('Updating system')
    if distribution == 'fedora':
        dnf_update_sources()
    else:
        apt_install_packages('apt-transport-https')
        apt_update_sources()
