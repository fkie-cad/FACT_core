import logging
from contextlib import suppress
from pathlib import Path
from shlex import split
from subprocess import PIPE, CalledProcessError, run

from .helperFunctions import InstallationError, OperateInDirectory


def install_postgres(version: int = 14):
    # based on https://www.postgresql.org/download/linux/ubuntu/
    command_list = [
        'sudo apt-get install -y postgresql-common',
        'sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y',
        f'sudo apt-get -y install postgresql-{version}',
    ]
    for command in command_list:
        process = run(command, text=True, shell=True, check=False, stderr=PIPE)
        if process.returncode != 0:
            raise InstallationError(f'Failed to set up PostgreSQL: {process.stderr}')

    # increase the maximum number of concurrent connections (and restart for the change to take effect)
    config_path = f'/etc/postgresql/{version}/main/postgresql.conf'
    run(f'sudo sed -i -E "s/max_connections = [0-9]+/max_connections = 999/g" {config_path}', shell=True, check=True)
    run('sudo service postgresql restart', shell=True, check=True)


def postgres_is_installed():
    try:
        run(split('psql --version'), check=True)
        return True
    except (CalledProcessError, FileNotFoundError):
        return False


def main():
    if postgres_is_installed():
        logging.info('Skipping PostgreSQL installation. Reason: Already installed.')
    else:
        logging.info('Setting up PostgreSQL database')
        install_postgres()

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
