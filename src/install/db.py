import logging
from contextlib import suppress
from pathlib import Path
from shlex import split
from subprocess import PIPE, CalledProcessError, run

from helperFunctions.install import InstallationError, OperateInDirectory

CODENAME_TRANSLATION = {
    'tara': 'bionic',
    'tessa': 'bionic',
    'tina': 'bionic',
    'tricia': 'bionic',
    'ulyana': 'focal',
    'ulyssa': 'focal',
    'uma': 'focal',
    'una': 'focal',
}


def install_postgres(version: int = 14):
    codename = run('lsb_release -cs', text=True, shell=True, stdout=PIPE, check=True).stdout.rstrip()
    codename = CODENAME_TRANSLATION.get(codename, codename)
    # based on https://www.postgresql.org/download/linux/ubuntu/
    command_list = [
        f'sudo sh -c \'echo "deb [arch=amd64] http://apt.postgresql.org/pub/repos/apt {codename}-pgdg main" > /etc/apt/sources.list.d/pgdg.list\'',  # noqa: E501
        'wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -',
        'sudo apt-get update',
        f'sudo apt-get -y install postgresql-{version}',
    ]
    for command in command_list:
        process = run(command, text=True, shell=True, check=False, stderr=PIPE)
        if process.returncode != 0:
            raise InstallationError(f'Failed to set up PostgreSQL: {process.stderr}')

    # increase the maximum number of concurrent connections (and restart for the change to take effect)
    config_path = f'/etc/postgresql/{version}/main/postgresql.conf'
    hba_config_path = f'/etc/postgresql/{version}/main/pg_hba.conf'
    run(f'sudo chmod 644 {hba_config_path}', shell=True, check=True)
    if '192.168.0.0/16' not in Path(hba_config_path).read_text():
        # for whatever reason, the local address ranges 10.0.0.0/8 and 192.168.0.0/16 are (contrary to 172.8.0.0/12) not
        # per default included in the list of allowed peer addresses for postgres, so we need to add it to pg_hba.conf,
        # so that the DB may be accessed from docker containers which sometimes get an address from this range
        for ip_range in ['192.168.0.0/16', '10.0.0.0/8 ']:
            run(f'echo "host all all {ip_range} scram-sha-256" | sudo tee -a {hba_config_path}', shell=True, check=True)
    run(f'sudo sed -i -E "s/max_connections = [0-9]+/max_connections = 999/g" {config_path}', shell=True, check=True)
    # set listen address from localhost to '*' (0.0.0.0) so that connections from docker containers are accepted
    run(
        f"sudo sed -i -E \"s/#? *listen_addresses = 'localhost'/listen_addresses = '\\*'/g\" {config_path}",
        shell=True,
        check=True,
    )
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
