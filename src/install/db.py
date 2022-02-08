import logging
import os
import subprocess
from contextlib import suppress
from pathlib import Path
from subprocess import PIPE, STDOUT

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
    grep_p = subprocess.run(r'grep -oP "dbPath:[\s]*\K[^\s]+" ../config/mongod.conf', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    if grep_p.returncode != 0:
        raise InstallationError('Unable to locate target for database directory')
    return grep_p.stdout.strip()


def _add_mongo_mirror(distribution):
    apt_key_p = subprocess.run(
        MONGO_MIRROR_COMMANDS[distribution]['key'],
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        universal_newlines=True,
    )
    tee_p = subprocess.run(
        MONGO_MIRROR_COMMANDS[distribution]['sources'],
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        universal_newlines=True,
    )
    if any(code != 0 for code in (apt_key_p.returncode, apt_key_p.returncode)):
        raise InstallationError('Unable to set up mongodb installation\n{}'.format('\n'.join((apt_key_p.stdout, tee_p.stdout))))


def main(distribution):
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
    mkdir_p = subprocess.run('sudo mkdir -p --mode=0744 {}'.format(fact_db_directory), shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    chown_p = subprocess.run('sudo chown {}:{} {}'.format(os.getuid(), os.getgid(), fact_db_directory), shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    if chown_p.returncode != 0:
        raise InstallationError('Failed to set up database directory. Check if parent folder exists\n{}'.format('\n'.join((mkdir_p.stdout, chown_p.stdout))))

    # initializing DB authentication
    logging.info('Initialize database')
    with OperateInDirectory('..'):
        init_database_p = subprocess.run('python3 init_database.py', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    if init_database_p.returncode != 0:
        raise InstallationError('Unable to initialize database\n{}'.format(init_database_p.stdout))

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_fact_db').unlink()
        Path('start_fact_db').symlink_to('src/start_fact_db.py')

    return 0
