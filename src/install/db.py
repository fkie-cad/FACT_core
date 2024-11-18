from __future__ import annotations

import logging
import re
from contextlib import suppress
from pathlib import Path
from shlex import split
from subprocess import PIPE, CalledProcessError, run

from helperFunctions.install import InstallationError, OperateInDirectory, check_distribution

POSTGRES_VERSION = 17
POSTGRES_UPDATE_MESSAGE = (
    'Please see  "https://github.com/fkie-cad/FACT_core/wiki/Upgrading-the-PostgreSQL-Database" for information on how'
    'to upgrade your PostgreSQL version.'
)


def install_postgres(version: int = POSTGRES_VERSION):
    # based on https://www.postgresql.org/download/linux/ubuntu/
    codename = check_distribution()
    command_list = [
        'sudo apt-get install -y postgresql-common',
        f'sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y {codename}',
        f'sudo apt-get -y install postgresql-{version}',
    ]
    for command in command_list:
        process = run(command, text=True, shell=True, check=False, stderr=PIPE)
        if process.returncode != 0:
            raise InstallationError(f'Failed to set up PostgreSQL: {process.stderr}')


def configure_postgres(version: int | None = None):
    if version is None:
        version = POSTGRES_VERSION
    config_path = f'/etc/postgresql/{version}/main/postgresql.conf'
    # increase the maximum number of concurrent connections
    run(f'sudo sed -i -E "s/max_connections = [0-9]+/max_connections = 999/g" {config_path}', shell=True, check=True)
    hba_config_path = f'/etc/postgresql/{version}/main/pg_hba.conf'
    # change UNIX domain socket auth mode from peer to user/pw
    run(f'sudo sed -i -E "s/(local +all +all +)peer/\\1scram-sha-256/g" {hba_config_path}', shell=True, check=True)
    # restart for the changes to take effect
    run('sudo service postgresql restart', shell=True, check=True)


def get_postgres_version() -> int:
    proc = run(split('psql --version'), text=True, capture_output=True, check=True)
    match = re.search(r'PostgreSQL\)? (\d+).\d+', proc.stdout)
    if match:
        return int(match.groups()[0])
    raise InstallationError(
        f'PostgreSQL is installed but version could not be identified: {proc.stdout}. {POSTGRES_UPDATE_MESSAGE}'
    )


def main():
    postgres_version: int | None = None
    try:
        postgres_version = get_postgres_version()
        if not postgres_version >= POSTGRES_VERSION:
            logging.warning(f'PostgreSQL is installed but the version is not up to date. {POSTGRES_UPDATE_MESSAGE}')
        logging.info('Skipping PostgreSQL installation. Reason: Already installed.')
    except (CalledProcessError, FileNotFoundError):  # psql binary was not found
        logging.info('Setting up PostgreSQL database')
        install_postgres()
    configure_postgres(postgres_version)

    # initializing DB
    logging.info('Initializing PostgreSQL database')
    with OperateInDirectory('..'):
        process = run('python3 init_postgres.py', shell=True, text=True, check=False, stderr=PIPE)
        if process.returncode != 0:
            raise InstallationError(f'Unable to initialize database\n{process.stderr}')

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_fact_database').unlink()
            # FIXME This can be removed after the next release that expects a rerun of the installer
            Path('start_fact_db').unlink()
        Path('start_fact_database').symlink_to('src/start_fact_database.py')

    return 0
