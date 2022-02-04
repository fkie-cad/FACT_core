import logging
import os
from contextlib import suppress
from pathlib import Path
from shlex import split
from subprocess import CalledProcessError, check_call

from common_helper_process import execute_shell_command, execute_shell_command_get_return_code

from helperFunctions.install import (
    InstallationError, OperateInDirectory, apt_install_packages, apt_update_sources, dnf_install_packages
)

MONGO_MIRROR_COMMANDS = {
    'debian': {
        'key': 'wget -qO - https://www.mongodb.org/static/pgp/server-3.6.asc | sudo apt-key add -',
        'sources': 'echo "deb http://repo.mongodb.org/apt/debian stretch/mongodb-org/3.6 main" | sudo tee /etc/apt/sources.list.d/mongo.list'
    },
}


def _get_db_directory():
    output, return_code = execute_shell_command_get_return_code(r'grep -oP "dbPath:[\s]*\K[^\s]+" ../config/mongod.conf')
    if return_code != 0:
        raise InstallationError('Unable to locate target for database directory')
    return output.strip()


def _add_mongo_mirror(distribution):
    apt_key_output, apt_key_code = execute_shell_command_get_return_code(
        MONGO_MIRROR_COMMANDS[distribution]['key']
    )
    tee_output, tee_code = execute_shell_command_get_return_code(
        MONGO_MIRROR_COMMANDS[distribution]['sources']
    )
    if any(code != 0 for code in (apt_key_code, tee_code)):
        raise InstallationError('Unable to set up mongodb installation\n{}'.format('\n'.join((apt_key_output, tee_output))))


CODENAME_TRANSLATION = {
    'tara': 'bionic', 'tessa': 'bionic', 'tina': 'bionic', 'tricia': 'bionic',
    'ulyana': 'focal', 'ulyssa': 'focal', 'uma': 'focal', 'una': 'focal',
}


def install_postgres():
    codename = execute_shell_command('lsb_release -cs').rstrip()
    codename = CODENAME_TRANSLATION.get(codename, codename)
    # based on https://www.postgresql.org/download/linux/ubuntu/
    command_list = [
        f'sudo sh -c \'echo "deb http://apt.postgresql.org/pub/repos/apt {codename}-pgdg main" > /etc/apt/sources.list.d/pgdg.list\'',
        'wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -',
        'sudo apt-get update',
        'sudo apt-get -y install postgresql-14'
    ]
    for command in command_list:
        output, return_code = execute_shell_command_get_return_code(command)
        if return_code != 0:
            raise InstallationError(f'Failed to set up PostgreSQL: {output}')


def postgres_is_installed():
    try:
        check_call(split('psql --version'))
        return True
    except (CalledProcessError, FileNotFoundError):
        return False


def main(distribution):
    if postgres_is_installed():
        logging.info('Skipping PostgreSQL installation. Reason: Already installed.')
    else:
        logging.info('Setting up PostgreSQL database')
        install_postgres()

    # delay import so that sqlalchemy is installed
    from install.init_postgres import main as init_postgres  # pylint: disable=import-outside-toplevel
    init_postgres()

    logging.info('Setting up mongo database')

    if distribution == 'debian':
        _add_mongo_mirror(distribution)
        apt_update_sources()
        apt_install_packages('mongodb-org')
    elif distribution == 'fedora':
        dnf_install_packages('mongodb-org-3.6.8')
    else:
        apt_install_packages('mongodb')

    # creating DB directory
    fact_db_directory = _get_db_directory()
    mkdir_output, _ = execute_shell_command_get_return_code(f'sudo mkdir -p --mode=0744 {fact_db_directory}')
    chown_output, chown_code = execute_shell_command_get_return_code(f'sudo chown {os.getuid()}:{os.getgid()} {fact_db_directory}')
    if chown_code != 0:
        raise InstallationError('Failed to set up database directory. Check if parent folder exists\n{}'.format('\n'.join((mkdir_output, chown_output))))

    # initializing DB authentication
    logging.info('Initialize database')
    with OperateInDirectory('..'):
        init_output, init_code = execute_shell_command_get_return_code('python3 init_database.py')
    if init_code != 0:
        raise InstallationError(f'Unable to initialize database\n{init_output}')

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_fact_db').unlink()
        Path('start_fact_db').symlink_to('src/start_fact_db.py')

    return 0
