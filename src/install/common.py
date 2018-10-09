import logging
import os
from contextlib import suppress

from common_helper_process import execute_shell_command_get_return_code

from helperFunctions.install import apt_remove_packages, apt_install_packages, apt_upgrade_system, apt_update_sources, \
    apt_autoremove_packages, apt_clean_system, InstallationError, pip_install_packages, install_github_project


def install_pip(python_command):
    logging.info('Installing {} pip'.format(python_command))
    for command in ['wget https://bootstrap.pypa.io/get-pip.py', 'sudo -EH {} get-pip.py'.format(python_command), 'rm get-pip.py']:
        output, return_code = execute_shell_command_get_return_code(command)
        if return_code != 0:
            raise InstallationError('Error in pip installation for {}:\n{}'.format(python_command, output))


def main(distribution):
    if distribution == 'xenial':
        xenial=True
        print('Installing on Ubuntu 16.04')
    elif distribution == 'bionic':
        xenial=False
        print('Installing on Ubuntu 18.04')
    else:
        raise InstallationError('Unsupported distribution {}'.format(distribution))

    apt_install_packages('apt-transport-https')

    logging.info('Updating system')
    apt_update_sources()
    apt_upgrade_system()
    apt_autoremove_packages()
    apt_clean_system()

    # change cwd to bootstrap dir
    # CURRENT_FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    # cd $CURRENT_FILE_DIR

    # update submodules
    # (cd.. /../ & & git submodule foreach 'git pull')

    # make bin dir
    with suppress(FileExistsError):
        os.mkdir('../bin')

    # set failsafe ssh environment for git
    # export GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

    # install python3 and general build stuff
    apt_install_packages('python3', 'python3-dev', 'build-essential', 'automake', 'autoconf', 'libtool', 'git', 'unzip')
    if not xenial:
        pip_install_packages('testresources')

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
    apt_install_packages('libffi-dev', 'libfuzzy-dev')
    pip_install_packages('psutil')
    pip_install_packages('pytest==3.5.1', 'pytest-cov', 'pytest-pep8', 'pylint', 'python-magic', 'xmltodict', 'yara-python==3.7.0', 'appdirs')
    pip_install_packages('ssdeep')
    pip_install_packages('lief')

    # install python mongo bindings
    pip_install_packages('pymongo', 'pyyaml')


    # ---- VarietyJS used for advanced search map generation ----
    # is executed by update_statistic.py
    try:
        install_github_project('variety/variety', ['git checkout 2f4d815', 'mv -f variety.js ../../bin', 'mv -f spec ../../bin'])
    except InstallationError as installation_error:
        if not 'Directory not empty' in str(installation_error):
            raise installation_error
        logging.warning('variety spec not overwritten')

    # echo "####################################"
    # echo "#  installing common code modules  #"
    # echo "####################################"

    # common_helper_files
    pip_install_packages('hurry.filesize')
    pip_install_packages('git+https://github.com/fkie-cad/common_helper_files.git')
    # common_helper_mongo
    pip_install_packages('git+https://github.com/fkie-cad/common_helper_mongo.git')
    # common_helper_encoder
    pip_install_packages('git+https://github.com/mass-project/common_helper_encoder.git')
    # common_helper_filter
    pip_install_packages('git+https://github.com/fkie-cad/common_helper_filter.git')


    # echo "####################################"
    # echo "#       install start script       #"
    # echo "####################################"
    # cd ../../
    # rm start_all_installed_fact_components
    # ln -s src/start_fact.py start_all_installed_fact_components

    return 0
