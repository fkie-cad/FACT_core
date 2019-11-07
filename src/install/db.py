import logging
import os
from contextlib import suppress
from pathlib import Path

from common_helper_process import execute_shell_command_get_return_code

from helperFunctions.install import InstallationError, OperateInDirectory, apt_install_packages, apt_update_sources

MONGO_MIRROR_COMMANDS = {
    'debian': {
        'key': 'wget -qO - https://www.mongodb.org/static/pgp/server-3.6.asc | sudo apt-key add -',
        'sources': 'echo "deb http://repo.mongodb.org/apt/debian stretch/mongodb-org/3.6 main" | sudo tee /etc/apt/sources.list.d/mongo.list'
    },
    'xenial': {
        'key': 'sudo -E apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 2930ADAE8CAF5059EE73BB4B58712A2291FA4AD5',
        'sources': 'echo "deb https://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.6 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.6.list'
    }
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


def main(distribution):
    logging.info('Setting up mongo database')

    if distribution in ['xenial', 'debian']:
        _add_mongo_mirror(distribution)
        apt_update_sources()
        apt_install_packages('mongodb-org')
    else:
        apt_install_packages('mongodb')

    # creating DB directory
    fact_db_directory = _get_db_directory()
    mkdir_output, _ = execute_shell_command_get_return_code('sudo mkdir -p --mode=0744 {}'.format(fact_db_directory))
    chown_output, chown_code = execute_shell_command_get_return_code('sudo chown {}:{} {}'.format(os.getuid(), os.getgid(), fact_db_directory))
    if chown_code != 0:
        raise InstallationError('Failed to set up database directory. Check if parent folder exists\n{}'.format('\n'.join((mkdir_output, chown_output))))

    # initializing DB authentication
    logging.info('Initialize database')
    with OperateInDirectory('..'):
        init_output, init_code = execute_shell_command_get_return_code('python3 init_database.py')
    if init_code != 0:
        raise InstallationError('Unable to initialize database\n{}'.format(init_output))

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_fact_db').unlink()
        Path('start_fact_db').symlink_to('src/start_fact_db.py')

    return 0
