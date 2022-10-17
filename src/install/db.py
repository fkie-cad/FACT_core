import logging
from contextlib import suppress
from pathlib import Path
from shlex import split
from subprocess import PIPE, CalledProcessError, run

from helperFunctions.install import InstallationError, OperateInDirectory

CODENAME_TRANSLATION = {
    'tara': 'bionic', 'tessa': 'bionic', 'tina': 'bionic', 'tricia': 'bionic',
    'ulyana': 'focal', 'ulyssa': 'focal', 'uma': 'focal', 'una': 'focal',
}


def install_postgres(version: int = 14):
    codename = run('lsb_release -cs', text=True, shell=True, stdout=PIPE, check=True).stdout.rstrip()
    codename = CODENAME_TRANSLATION.get(codename, codename)
    # based on https://www.postgresql.org/download/linux/ubuntu/
    command_list = [
        f'sudo sh -c \'echo "deb [arch=amd64] http://apt.postgresql.org/pub/repos/apt {codename}-pgdg main" > /etc/apt/sources.list.d/pgdg.list\'',
        'wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -',
        'sudo apt-get update',
        f'sudo apt-get -y install postgresql-{version}'
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
            Path('start_fact_db').unlink()
        Path('start_fact_db').symlink_to('src/start_fact_db.py')

    return 0
